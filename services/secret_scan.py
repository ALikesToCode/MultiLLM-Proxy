"""Bounded JSON-leaf secret detection; findings contain offsets, never values."""

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re

MAX_BYTES = 4_194_304
MAX_FINDINGS = 4096
MAX_NODES = 100_000
MAX_DEPTH = 64
_PATTERNS = [(name, re.compile(pattern, re.ASCII)) for name, pattern in json.loads(
    (Path(__file__).resolve().parents[1] / "worker/secret-patterns.json").read_text()).items()]
_KEY_MARKER = re.compile(r"-----(BEGIN|END) ([A-Z0-9 ]{0,32}PRIVATE KEY)-----")
_ASSIGN = re.compile(r"(?<![A-Za-z0-9_.-])[\"']?([A-Za-z_][A-Za-z0-9_.-]{0,127})[\"']?[ \t]*[=:][ \t]*[\"']?([^\s\"',;}{]{12,4096})")
_FIELD = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH", re.I)
_EXAMPLE = re.compile(r"xxx|your_|example|placeholder|changeme|\*\*\*|REDACTED|dummy", re.I)
_UUID = re.compile(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}\Z")
_BINARY_FIELDS = frozenset({"b64_json", "audio", "data", "image", "images"})
# Match the header in one pass, then validate parameter pairs without nested repeats.
_DATA_URL_PATTERN = r"data:[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+;[A-Za-z0-9_.+=;-]*base64,[A-Za-z0-9+/= \t\r\n]+"
_DATA_URL = re.compile(_DATA_URL_PATTERN, re.ASCII)
_DATA_PARAM = re.compile(r"[A-Za-z0-9_.+-]+=[A-Za-z0-9_.+-]+\Z", re.ASCII)
_INTEGRITY_PATTERN = r"(?<![A-Za-z0-9_-])sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}(?![A-Za-z0-9+/=_-])"
_INTEGRITY = re.compile(_INTEGRITY_PATTERN, re.ASCII)
_IGNORED_SPAN = re.compile(_DATA_URL_PATTERN + "|" + _INTEGRITY_PATTERN, re.ASCII)
_BASE64 = re.compile(r"[A-Za-z0-9+/=\r\n]+\Z")


def _example(value):
    delimited = any((start := value.find(begin)) >= 0 and value.find(end, start + len(begin)) >= 0
                    for begin, end in (("<", ">"), ("${", "}"), ("{{", "}}")))
    return bool(delimited or _EXAMPLE.search(value) or _UUID.fullmatch(value)
                or len(set(value)) < 2 or _INTEGRITY.fullmatch(value))


def _entropy(value):
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def _heuristic(value):
    return len(value) >= 12 and not _example(value) and _entropy(value) >= 3.0


def _valid_data_url(value):
    header = value.partition(",")[0].split(";")
    return header[-1] == "base64" and all(_DATA_PARAM.fullmatch(part) for part in header[1:-1])


def _skipped(value, field=""):
    return bool(_DATA_URL.fullmatch(value) and _valid_data_url(value)) or (
        field in _BINARY_FIELDS and len(value) >= 128 and bool(_BASE64.fullmatch(value)))


def scan_text(text):
    """Code-point offsets, sorted and non-overlapping; specific formats win."""
    if not isinstance(text, str):
        return []
    text = text[:MAX_BYTES]
    candidates = []
    pending = None
    for match in _KEY_MARKER.finditer(text):
        if match[1] == "BEGIN":
            pending = (match.start(), match[2])
        elif pending and pending[1] == match[2]:
            start = pending[0]
            if not _example(text[start:match.end()]):
                candidates.append((start, match.end(), "private_key", "high"))
            pending = None
            if len(candidates) >= MAX_FINDINGS:
                break
    for name, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            if name == "generic_sk_key":
                final = match[0].rsplit("-", 1)[-1]
                if not re.search(r"[0-9]", final) or not re.search(r"[A-Za-z]", final):
                    continue
            if not _example(match[0]):
                candidates.append((match.start(), match.end(), name, "high"))
            if len(candidates) >= MAX_FINDINGS:
                break
        if len(candidates) >= MAX_FINDINGS:
            break
    for match in _ASSIGN.finditer(text):
        if _FIELD.search(match[1]) and _heuristic(match[2]):
            candidates.append((match.start(2), match.end(2), "secret_assignment", "heuristic"))
        if len(candidates) >= MAX_FINDINGS:
            break
    # Walk ordered spans once; only candidates wholly inside binary/integrity text
    # are excluded. A prefix on a pasted log must never exempt the rest of the leaf.
    spans = (match for match in _IGNORED_SPAN.finditer(text)
             if not match[0].startswith("data:") or _valid_data_url(match[0]))
    span = next(spans, None)
    visible = []
    for item in sorted(candidates, key=lambda item: item[0]):
        while span and span.end() <= item[0]:
            span = next(spans, None)
        if not span or item[0] < span.start() or item[1] > span.end():
            visible.append(item)
    candidates = visible
    high = sorted((item for item in candidates if item[3] == "high"), key=lambda item: (item[0], -item[1]))
    heuristic = sorted(item for item in candidates if item[3] == "heuristic")
    selected, last_end = [], -1
    for item in high:
        if item[0] >= last_end:
            selected.append(item)
            last_end = item[1]
    cursor = 0
    for item in heuristic:
        while cursor < len(selected) and selected[cursor][1] <= item[0]:
            cursor += 1
        if cursor == len(selected) or selected[cursor][0] >= item[1]:
            high.append(item)
    candidates = high
    candidates.sort(key=lambda item: (item[0], item[3] != "high", -item[1]))
    result, end = [], -1
    for start, stop, name, confidence in candidates:
        if start >= end:
            result.append({"type": name, "confidence": confidence, "start": start, "end": stop})
            end = stop
    return result


def redact_text(text, findings):
    parts, position = [], 0
    for finding in findings:
        if finding["confidence"] != "high":
            continue
        start, end = finding["start"], finding["end"]
        parts.append(text[position:start])
        digest = hashlib.sha256(text[start:end].encode("utf-8")).hexdigest()[:6]
        parts.append(f"[REDACTED:{finding['type']}:{digest}]")
        position = end
    parts.append(text[position:])
    return "".join(parts)


def _walk(value, max_bytes, redact=False):
    report = {"high": 0, "heuristic": 0, "types": {}, "paths": [], "truncated": False}
    remaining, nodes = max(0, int(max_bytes)), 0

    def visit(item, path, field, depth):
        nonlocal remaining, nodes
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            report["truncated"] = True
            return item
        if isinstance(item, str):
            if _skipped(item, field):
                return item
            # Encode only a bounded prefix, even for a single enormous leaf.
            prefix = item[:remaining].encode("utf-8")[:remaining].decode("utf-8", "ignore")
            used = len(prefix.encode("utf-8"))
            remaining -= used
            if len(prefix) != len(item):
                report["truncated"] = True
            findings = scan_text(prefix)
            if not findings and _FIELD.search(field) and _heuristic(prefix) and prefix == item:
                findings = [{"type": "secret_field", "confidence": "heuristic", "start": 0, "end": len(prefix)}]
            for finding in findings:
                report[finding["confidence"]] += 1
                name = finding["type"]
                report["types"][name] = report["types"].get(name, 0) + 1
            if findings and len(report["paths"]) < 20:
                report["paths"].append(path)
            if len(findings) >= MAX_FINDINGS:
                report["truncated"] = True
            return redact_text(prefix, findings) + item[len(prefix):] if redact and findings else item
        if isinstance(item, (dict, list)):
            output = None
            entries = item.items() if isinstance(item, dict) else enumerate(item)
            for key, child in entries:
                if nodes >= MAX_NODES:
                    report["truncated"] = True
                    break
                child_field = str(key) if isinstance(item, dict) else field
                child_path = path + ("[" + json.dumps(str(key), ensure_ascii=False) + "]" if isinstance(item, dict) else f"[{key}]")
                updated = visit(child, child_path, child_field, depth + 1)
                if updated is not child:
                    if output is None:
                        output = item.copy()
                    output[key] = updated
            return item if output is None else output
        return item

    result = visit(value, "$", "", 0)
    return result, report


def scan_payload(value, *, max_bytes=MAX_BYTES):
    return _walk(value, max_bytes)[1]


def redact_payload(value, *, mode):
    if mode not in {"off", "observe", "redact", "block"}:
        raise ValueError("Unsupported secret scan mode")
    if mode == "off":
        return value, {"high": 0, "heuristic": 0, "types": {}, "paths": [], "truncated": False}
    return _walk(value, MAX_BYTES, redact=mode == "redact")
