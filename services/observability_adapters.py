"""Explicit content-free collectors, independent of the OTLP exporter."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import re
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)
MAX_QUEUE = 1000
BATCH_SIZE = 50
TIMEOUT = 2
RETRIES = 2
_warned = False
_KINDS = {"chat", "responses", "embeddings", "images", "audio", "proxy", "shadow", "canary", "roleplay"}
_OUTCOMES = {"success", "unknown", "upstream_error", "transport_error", "canceled"}
_BASES = {"usage", "estimate", "cache"}
_PROVENANCE = {"provider", "request_estimate", "cache", "measured", "estimated", "unknown"}


@dataclass(frozen=True)
class Destination:
    type: str
    endpoint: str
    credential_env: str


def _origin(value: str, *, origin_only: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 2048 or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise ValueError("Invalid destination")
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None
            or "?" in value or "#" in value or origin_only and url.path not in {"", "/"}):
        raise ValueError("Invalid destination")
    port = url.port
    host = url.hostname.lower()
    host = f"[{host}]" if ":" in host else host
    return f"https://{host}" + (f":{port}" if port not in {None, 443} else "")


def destinations(raw: str) -> tuple[Destination, ...]:
    global _warned
    if raw is None or isinstance(raw, str) and not raw.strip():
        return ()
    try:
        if not isinstance(raw, str) or len(raw) > 32768:
            raise ValueError("Configuration too large")
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) > 8:
            raise ValueError("Invalid exporters")
        result = []
        for value in values:
            if (not isinstance(value, dict) or set(value) != {"type", "endpoint", "allowed_origins", "credential_env"}
                    or value["type"] not in {"langfuse", "helicone"}
                    or not isinstance(value["credential_env"], str)
                    or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}_EXPORT_CREDENTIAL", value["credential_env"])
                    or not isinstance(value["allowed_origins"], list) or not 1 <= len(value["allowed_origins"]) <= 16):
                raise ValueError("Invalid exporter")
            origin = _origin(value["endpoint"])
            if origin not in {_origin(item, origin_only=True) for item in value["allowed_origins"]}:
                raise ValueError("Destination not allowed")
            item = Destination(value["type"], value["endpoint"], value["credential_env"])
            if item in result:
                raise ValueError("Duplicate exporter")
            result.append(item)
        return tuple(result)
    except (ValueError, TypeError, KeyError, RecursionError):
        if not _warned:
            _warned = True
            logger.warning("Invalid OBSERVABILITY_EXPORTERS_JSON; exports disabled")
        return ()


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 256 and not re.search(r"[\x00-\x1f\x7f]", value) else None


def _number(value: Any) -> int | float | None:
    return value if type(value) in {int, float} and 0 <= value <= 2**53 - 1 and math.isfinite(value) else None


def _tokens(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**53 - 1 else None


def _timestamp(value: Any) -> str | None:
    try:
        if isinstance(value, str) and len(value) <= 40 and value.endswith("Z"):
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        elif type(value) is int and 0 <= value <= 253402300799000000000:
            moment = datetime.fromtimestamp(value / 1_000_000_000, timezone.utc)
        else:
            return None
        return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def observation(record: dict, origin: str) -> dict | None:
    """Allowlist scalar metadata; never traverse payloads, headers or error messages."""
    request_id = _text(record.get("request_id"))
    principal = _text(record.get("principal"))
    if not request_id or not principal or origin not in {"flask", "worker"}:
        return None
    status = _tokens(record.get("status"))
    status = status if status is not None and 100 <= status <= 599 else None
    basis = record.get("cost_basis")
    basis = basis if isinstance(basis, str) and basis in _BASES else None
    usage_basis = record.get("usage_basis")
    usage_basis = usage_basis if isinstance(usage_basis, str) and usage_basis in _PROVENANCE else (
        "estimated" if basis == "estimate" else "provider" if basis == "usage" else "unknown")
    provenance = record.get("provenance")
    provenance = [item for item in provenance[:16] if isinstance(item, str) and item in _PROVENANCE] if isinstance(provenance, (list, tuple)) else [usage_basis]
    kind = record.get("kind")
    kind = kind if isinstance(kind, str) and kind in _KINDS else "proxy"
    outcome = record.get("outcome")
    outcome = outcome if isinstance(outcome, str) and outcome in _OUTCOMES else (
        "upstream_error" if status is not None and status >= 400 else "unknown")
    end = _timestamp(record.get("end_ns")) or _timestamp(record.get("at"))
    start = _timestamp(record.get("start_ns"))
    latency = _number(record.get("latency_ms"))
    if start is None and end is not None and latency is not None and latency <= 86_400_000:
        start = (datetime.fromisoformat(end.replace("Z", "+00:00")) - timedelta(milliseconds=latency)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"request_id": request_id, "correlation_id": _text(record.get("trace_id")),
            "principal": "principal:" + hashlib.sha256(principal.encode()).hexdigest(), "origin": origin,
            "model": _text(record.get("selected_model")), "kind": kind, "status": status,
            "error": outcome if outcome in {"upstream_error", "transport_error", "canceled"} else None,
            "outcome": outcome, "start_time": start, "end_time": end,
            "latency_ms": latency, "ttft_ms": _number(record.get("ttft_ms")),
            "usage": {"input_tokens": _tokens(record.get("input_tokens")), "output_tokens": _tokens(record.get("output_tokens")), "basis": usage_basis},
            "cost": {"usd": _number(record.get("cost_usd")), "basis": basis}, "provenance": provenance}


def _event_id(item: dict) -> str:
    return hashlib.sha256(json.dumps([item["origin"], item["request_id"], item["kind"]]).encode()).hexdigest()


def _helicone_time(value: str | None) -> dict | None:
    if value is None:
        return None
    millis = int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    return {"seconds": millis // 1000, "milliseconds": millis % 1000}


def payloads(destination: Destination, batch: list[dict]) -> list[dict]:
    if destination.type == "langfuse":
        return [{"batch": [{"id": _event_id(item), "type": "generation-create",
                            "timestamp": item["end_time"], "body": {
                                "id": _event_id(item), "traceId": item["correlation_id"] or item["request_id"],
                                "name": f"multillm.{item['kind']}", "model": item["model"],
                                "startTime": item["start_time"], "endTime": item["end_time"],
                                "usage": {"input": item["usage"]["input_tokens"], "output": item["usage"]["output_tokens"], "unit": "TOKENS"},
                                "metadata": item}} for item in batch]}]
    return [{"providerRequest": {"url": "https://multillm.invalid", "json": {"model": item["model"]},
                 "meta": {"Helicone-Request-Id": _event_id(item), "Helicone-User-Id": item["principal"],
                          "Helicone-Property-observation": json.dumps(item, separators=(",", ":"))}},
             "providerResponse": {"status": item["status"], "headers": {}, "json": {
                 "usage": {"prompt_tokens": item["usage"]["input_tokens"], "completion_tokens": item["usage"]["output_tokens"]}}},
             "timing": {"startTime": _helicone_time(item["start_time"]), "endTime": _helicone_time(item["end_time"])}} for item in batch]


def _receipt(response, payload: dict) -> int:
    """A partial ingestion receipt acknowledges only explicit successful event IDs."""
    if response.status_code != 207:
        return (len(payload["batch"]) if "batch" in payload else 1) if 200 <= response.status_code < 300 else 0
    if "batch" not in payload:
        return 0
    try:
        content = response.raw.read(32769) if hasattr(response, "raw") else response.content
        if len(content) > 32768:
            return 0
        receipt = json.loads(content)
        if not isinstance(receipt, dict) or not isinstance(receipt.get("successes"), list) or not isinstance(receipt.get("errors"), list):
            return 0
        successes = {item.get("id") for item in receipt["successes"] if isinstance(item, dict) and isinstance(item.get("id"), str)}
        errors = {item.get("id") for item in receipt["errors"] if isinstance(item, dict) and isinstance(item.get("id"), str)}
        return sum(item["id"] in successes and item["id"] not in errors for item in payload["batch"])
    except (AttributeError, ValueError, TypeError, RecursionError):
        return 0


class ObservabilityExporter:
    def __init__(self, env: Mapping[str, str] | None = None, *, transport=None, auto_start: bool = True) -> None:
        self.env = os.environ if env is None else env
        self.transport = transport
        self.auto_start = auto_start
        self._raw: str | None = None
        self._destinations: tuple[Destination, ...] = ()
        self._queue: deque = deque()
        self._seen: dict[tuple, None] = {}
        self._lock = threading.Lock()
        self._delivery_lock = threading.Lock()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats: dict[Destination, dict] = {}
        self.accepted = self.dropped = 0

    def _configure(self) -> tuple[Destination, ...]:
        raw = self.env.get("OBSERVABILITY_EXPORTERS_JSON", "")
        if raw != self._raw:
            self._raw = raw
            self._destinations = destinations(raw)
        return self._destinations

    def submit(self, record: dict, *, origin: str = "flask") -> bool:
        with self._lock:
            targets = self._configure()
            if not targets:
                return False
            item = observation(record, origin)
            if item is None:
                self.dropped += 1
                return False
            identity = (origin, item["request_id"], item["kind"])
            if identity in self._seen:
                return False
            if len(self._queue) >= MAX_QUEUE:
                self.dropped += 1
                return False
            self._seen[identity] = None
            if len(self._seen) > MAX_QUEUE:
                del self._seen[next(iter(self._seen))]
            self._queue.append((targets, item))
            self.accepted += 1
            if self.auto_start and (self._thread is None or not self._thread.is_alive()):
                self._thread = threading.Thread(target=self._run, name="observability-export", daemon=True)
                self._thread.start()
        self._wake.set()
        return True

    def _run(self) -> None:
        while True:
            self._wake.wait(5)
            self._wake.clear()
            try:
                while self.export_once():
                    pass
            except Exception:
                logger.warning("Observability export failed")

    def _deliver(self, target: Destination, batch: list[dict]) -> None:
        stats = self._stats.setdefault(target, {"acknowledged": 0, "failed": 0, "attempts": 0, "delivery_status": "idle"})
        credential = self.env.get(target.credential_env, "")
        if not isinstance(credential, str) or not credential or len(credential) > 8192 or re.search(r"[\x00-\x1f\x7f]", credential):
            stats["failed"] += len(batch)
            stats["delivery_status"] = "credential_unavailable"
            return
        authorization = "Basic " + base64.b64encode(credential.encode()).decode() if target.type == "langfuse" else "Bearer " + credential
        for payload in payloads(target, batch):
            count = len(batch) if target.type == "langfuse" else 1
            acknowledged = 0
            for _ in range(RETRIES + 1):
                stats["attempts"] += 1
                try:
                    response = (self.transport or requests.post)(target.endpoint, json=payload,
                        headers={"Content-Type": "application/json", "Authorization": authorization},
                        timeout=TIMEOUT, allow_redirects=False, stream=True)
                    try:
                        code = response.status_code
                        acknowledged = _receipt(response, payload)
                        if acknowledged or code != 429 and code < 500:
                            break
                    finally:
                        if hasattr(response, "close"):
                            response.close()
                except Exception:
                    pass
            stats["acknowledged"] += acknowledged
            stats["failed"] += count - acknowledged
            stats["delivery_status"] = "acknowledged" if acknowledged == count else "partial" if acknowledged else "failed"

    def export_once(self) -> int:
        with self._delivery_lock:
            with self._lock:
                batch = [self._queue.popleft() for _ in range(min(BATCH_SIZE, len(self._queue)))]
            groups: dict[Destination, list[dict]] = {}
            for targets, item in batch:
                for target in targets:
                    groups.setdefault(target, []).append(item)
            for target, records in groups.items():
                self._deliver(target, records)
            with self._lock:
                retained = set(self._destinations)
                for targets, _ in self._queue:
                    retained.update(targets)
                self._stats = {target: stats for target, stats in self._stats.items() if target in retained}
            return len(batch)

    def status(self) -> dict:
        with self._lock:
            return {"accepted": self.accepted, "dropped": self.dropped, "queued": len(self._queue),
                    "exporters": [{"type": target.type, "credential_env": target.credential_env,
                                   **self._stats.get(target, {"acknowledged": 0, "failed": 0, "attempts": 0, "delivery_status": "idle"})}
                                  for target in self._configure()]}


OBSERVABILITY_EXPORTER = ObservabilityExporter()
