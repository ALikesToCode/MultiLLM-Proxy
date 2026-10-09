"""Bounded, content-free heuristics at explicit managed request boundaries."""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import unicodedata
from dataclasses import dataclass

from flask import g, request

HEADER = "X-MultiLLM-Injection-Action"
MAX_BYTES = 1_048_576
MAX_FINDINGS = 256
MAX_NODES = 8192
_RANK = {"off": 0, "log": 1, "block": 2}
_warned: set[str] = set()
_warning_lock = threading.Lock()
logger = logging.getLogger(__name__)

# Every repetition has a fixed bound; alternatives have no recursive structure.
_RULES = (
    ("instruction_override", "high", 3, re.compile(
        r"\b(?:ignore|disregard|override|forget)[ \t\r\n]{1,16}(?:all[ \t\r\n]{1,16})?"
        r"(?:(?:previous|prior|above|system|developer)[ \t\r\n]{1,16}){1,2}(?:instructions|rules|prompts)\b", re.ASCII)),
    ("role_spoof", "high", 3, re.compile(
        r"<\|(?:im_start|start_header_id)\|>[ \t\r\n]{0,16}(?:system|developer)\b"
        r"|</?(?:system|developer)>|\[inst\]|<<sys>>|```[ \t\r\n]{0,16}(?:system|developer)\b"
        r"|\bsystem[ \t\r\n]{0,8}:[ \t\r\n]{0,8}override\b", re.ASCII)),
    ("secret_exfiltration", "high", 3, re.compile(
        r"\b(?:reveal|extract|exfiltrate|leak|print|send)[ \t\r\n]{1,16}"
        r"(?:(?:the|your|all)[ \t\r\n]{1,16})?(?:system[ \t\r\n]{1,16}prompt|api[ _-]?keys?"
        r"|passwords?|credentials|secrets|access[ _-]?tokens?)\b", re.ASCII)),
    ("jailbreak_mode", "medium", 2, re.compile(
        r"\b(?:developer|unrestricted|jailbreak)[ \t\r\n]{1,16}mode\b"
        r"|\b(?:disable|bypass)[ \t\r\n]{1,16}(?:safety|guardrails|restrictions)\b", re.ASCII)),
)
_ENCODING = re.compile(r"&#(?:x[0-9a-f]{1,6}|[0-9]{1,7});|&(?:lt|gt|amp|quot);|%[0-9a-f]{2}|\\u[0-9a-f]{4}")


def _warn_once(setting):
    with _warning_lock:
        if setting in _warned:
            return
        _warned.add(setting)
    logger.warning("Invalid %s; prompt injection controls disabled", setting)


def _threshold(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= MAX_FINDINGS * 3 else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,3}", value.strip()):
        return _threshold(int(value))
    return None


def resolve_policy(env=None, *, policies=()):
    env = os.environ if env is None else env
    raw = env.get("PROMPT_INJECTION_MODE", "")
    mode = raw.strip().lower() if isinstance(raw, str) else "invalid"
    if not mode or mode == "off":
        return "off", 3
    if mode not in _RANK:
        _warn_once("PROMPT_INJECTION_MODE")
        return "off", 3
    raw = env.get("PROMPT_INJECTION_THRESHOLD", "")
    threshold = _threshold("3" if raw is None or isinstance(raw, str) and not raw.strip() else raw)
    if threshold is None:
        _warn_once("PROMPT_INJECTION_THRESHOLD")
        return "off", 3
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        tighter_mode = policy.get("mode")
        if isinstance(tighter_mode, str) and tighter_mode in _RANK:
            mode = max((mode, tighter_mode), key=_RANK.__getitem__)
        tighter_threshold = _threshold(policy.get("threshold"))
        if tighter_threshold is not None:
            threshold = min(threshold, tighter_threshold)
    return mode, threshold


def _decode(match):
    value = match[0]
    if value.startswith("&#"):
        code = int(value[3:-1], 16) if value.startswith("&#x") else int(value[2:-1])
    elif value.startswith("%"):
        code = int(value[1:], 16)
    elif value.startswith("\\u"):
        code = int(value[2:], 16)
    else:
        return {"&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"'}[value]
    # Delimiter decoding is deliberately ASCII-only, with no recursive decoding.
    return chr(code) if code < 128 else value


def _normalize(text):
    # Normalize code points independently to avoid adversarial combining-mark
    # reordering across a long string. The ASCII fast path preserves rule parity.
    text = text.lower() if text.isascii() else "".join(unicodedata.normalize("NFKC", char).lower() for char in text)
    text = _ENCODING.sub(_decode, text)
    return "".join(char for char in text if char in "\t\r\n" or unicodedata.category(char) not in {"Cc", "Cf"})


def _text_nodes(payload, budget):
    if not isinstance(payload, dict):
        return
    stack = [iter(payload.get(key) for key in ("messages", "contents", "input", "prompt"))]
    while stack:
        try:
            value = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        budget[0] += 1
        if budget[0] > MAX_NODES:
            budget[1] = True
            return
        if isinstance(value, str):
            yield value
        elif isinstance(value, list):
            stack.append(iter(value))
        elif isinstance(value, dict):
            if "role" in value and value["role"] not in ("user", "tool", "function"):
                continue
            stack.append(iter(tuple(value.get(key) for key in ("content", "text", "parts", "output"))))


@dataclass(frozen=True)
class InjectionDecision:
    mode: str
    action: str | None
    report: dict | None


def evaluate(payload, env=None, *, policies=(), managed=True):
    """Return aggregates only; never retain text or authorize another dispatch."""
    if not managed:
        return InjectionDecision("off", None, None)
    mode, threshold = resolve_policy(env, policies=policies)
    if mode == "off":
        return InjectionDecision(mode, None, None)
    report = {"rules": {}, "severity": {}, "count": 0, "score": 0,
              "scanned_bytes": 0, "truncated": False}
    budget = [0, False]
    for text in _text_nodes(payload, budget):
        remaining = MAX_BYTES - report["scanned_bytes"]
        # Slice before encoding so an arbitrarily long string cannot amplify work.
        bounded = text[:remaining].encode("utf-8", errors="replace")
        if len(bounded) > remaining or len(text) > remaining:
            report["truncated"] = True
        bounded = bounded[:remaining]
        report["scanned_bytes"] += len(bounded)
        normalized = _normalize(bounded.decode("utf-8", errors="ignore"))
        for rule, severity, score, pattern in _RULES:
            for _ in pattern.finditer(normalized):
                report["rules"][rule] = report["rules"].get(rule, 0) + 1
                report["severity"][severity] = report["severity"].get(severity, 0) + 1
                report["count"] += 1
                report["score"] += score
                if report["count"] == MAX_FINDINGS:
                    break
            if report["count"] == MAX_FINDINGS:
                break
        if report["count"] == MAX_FINDINGS or report["scanned_bytes"] == MAX_BYTES:
            report["truncated"] = True
            break
    report["truncated"] = report["truncated"] or budget[1]
    action = ("blocked" if mode == "block" else "logged") if report["score"] >= threshold else None
    return InjectionDecision(mode, action, report)


def record_security_event(decision):
    """Log aggregates without identity, route or content strings."""
    if decision.action is None:
        return
    detail = json.dumps({"kind": "prompt_injection", "mode": decision.mode,
                         "action": decision.action, **decision.report}, separators=(",", ":"))
    logger.info("prompt_injection %s", detail)


def register_prompt_injection(app, *, is_managed, route_policy=None):
    """Inject route eligibility after authentication/retention and before identity/admission."""
    if app.extensions.get("prompt_injection_registered"):
        return
    def prompt_injection_request_hook():
        # Off must avoid eligibility checks and JSON parsing as well as scanning.
        if resolve_policy()[0] == "off" or not is_managed():
            return None
        from services.secret_firewall import protect_managed_payload
        from error_handlers import APIError
        policy = route_policy() if route_policy is not None else None
        try:
            protect_managed_payload(request.get_json(silent=True), user=getattr(g, "authenticated_user", None),
                                    route_policy=policy)
        except APIError as error:
            # Internal batch items invoke hooks in a nested request context,
            # rather than Flask's outer exception dispatcher.
            if not getattr(g, "gateway_batch_execution", False):
                raise
            from flask import jsonify
            return jsonify(error.to_dict()), error.status_code
        return None

    from services.gateway_extensions import register_authenticated_hook
    register_authenticated_hook(app, prompt_injection_request_hook)
    app.extensions["prompt_injection_registered"] = True
