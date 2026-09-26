"""Optional OTLP/HTTP JSON export of request spans and metrics.

Off unless `OTEL_EXPORTER_OTLP_ENDPOINT` (or a per-signal endpoint) is set. Requests
only enqueue a small record; a background thread sends batches, and a full queue drops
the newest record and counts it. Spans and metrics carry the route kind, models, status,
latency, token counts, estimated cost and the account name. They never carry prompts,
outputs, API keys or key prefixes.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from typing import Any, Optional
from urllib.parse import unquote

import requests

logger = logging.getLogger(__name__)

MAX_QUEUE = 2048
BATCH_SIZE = 256
EXPORT_SECONDS = 5.0
TIMEOUT = (3, 5)
_TRACEPARENT = re.compile(r"00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}\Z")
SPAN_KIND_SERVER = 2
STATUS_ERROR = 2
DELTA = 1


def configured() -> bool:
    return any(os.environ.get(name, "").strip() for name in (
        "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"))


def endpoint(signal: str) -> Optional[str]:
    """The per-signal endpoint as-is, else the base endpoint plus /v1/<signal>."""
    specific = os.environ.get(f"OTEL_EXPORTER_OTLP_{signal.upper()}_ENDPOINT", "").strip()
    if specific:
        return specific
    base = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    return f"{base.rstrip('/')}/v1/{signal}" if base else None


def headers(signal: str) -> dict[str, str]:
    """`key=value` pairs, comma-separated, values percent-decoded (W3C baggage format)."""
    result = {"Content-Type": "application/json"}
    for name in ("OTEL_EXPORTER_OTLP_HEADERS", f"OTEL_EXPORTER_OTLP_{signal.upper()}_HEADERS"):
        for item in os.environ.get(name, "").split(","):
            key, separator, value = item.partition("=")
            if separator and key.strip() and re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", key.strip()):
                result[key.strip()] = unquote(value.strip())
    return result


def _attribute(key: str, value: Any) -> Optional[dict]:
    if value is None:
        return None
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)[:256]}}


def _attributes(values: dict) -> list[dict]:
    return [item for item in (_attribute(key, value) for key, value in values.items()) if item]


def trace_context(header: Optional[str]) -> tuple[str, Optional[str]]:
    """Continue a caller's W3C trace when it sent a valid traceparent header."""
    match = _TRACEPARENT.fullmatch((header or "").strip().lower())
    if match and match.group(1) != "0" * 32 and match.group(2) != "0" * 16:
        return match.group(1), match.group(2)
    return secrets.token_hex(16), None


class TelemetryExporter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue: deque = deque()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats = {"exported": 0, "dropped": 0, "failed_exports": 0}

    def submit(self, record: dict) -> bool:
        if not configured():
            return False
        with self._lock:
            if len(self._queue) >= MAX_QUEUE:
                self.stats["dropped"] += 1
                return False
            self._queue.append(record)
            full = len(self._queue) >= BATCH_SIZE
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="otlp-export", daemon=True)
                self._thread.start()
        if full:
            self._wake.set()
        return True

    def _run(self) -> None:
        while True:
            self._wake.wait(EXPORT_SECONDS)
            self._wake.clear()
            try:
                self.export_once()
            except Exception as error:  # Telemetry must never affect serving.
                logger.warning("Telemetry export failed (%s)", type(error).__name__)

    def export_once(self) -> int:
        with self._lock:
            batch = [self._queue.popleft() for _ in range(min(BATCH_SIZE, len(self._queue)))]
        if not batch:
            return 0
        resource = {"attributes": _attributes({
            "service.name": os.environ.get("OTEL_SERVICE_NAME", "").strip() or "multillm-proxy"})}
        scope = {"name": "multillm-proxy.usage"}
        sent = False
        for signal, payload in (("traces", {"resourceSpans": [{"resource": resource, "scopeSpans": [
                {"scope": scope, "spans": [span(record) for record in batch]}]}]}),
                                ("metrics", {"resourceMetrics": [{"resource": resource, "scopeMetrics": [
                                    {"scope": scope, "metrics": metrics(batch)}]}]})):
            target = endpoint(signal)
            if not target:
                continue
            try:
                response = requests.post(target, json=payload, headers=headers(signal), timeout=TIMEOUT,
                                         allow_redirects=False)
                if response.status_code >= 300:
                    raise ValueError(f"HTTP {response.status_code}")
                sent = True
            except Exception as error:
                self.stats["failed_exports"] += 1
                logger.warning("OTLP %s export failed (%s)", signal, str(error)[:80] or type(error).__name__)
        if sent:
            self.stats["exported"] += len(batch)
        return len(batch)

    def reset(self) -> None:
        with self._lock:
            self._queue.clear()
            self.stats = {"exported": 0, "dropped": 0, "failed_exports": 0}


def span(record: dict) -> dict:
    result = {
        "traceId": record["trace_id"],
        "spanId": secrets.token_hex(8),
        "name": f"multillm.{record['kind']}",
        "kind": SPAN_KIND_SERVER,
        "startTimeUnixNano": str(record["start_ns"]),
        "endTimeUnixNano": str(record["end_ns"]),
        "attributes": _attributes({
            "http.request.method": record.get("method"),
            "url.path": record.get("endpoint"),
            "http.response.status_code": record.get("status"),
            "multillm.kind": record.get("kind"),
            "gen_ai.request.model": record.get("requested_model"),
            "gen_ai.response.model": record.get("selected_model"),
            "gen_ai.usage.input_tokens": record.get("input_tokens"),
            "gen_ai.usage.output_tokens": record.get("output_tokens"),
            "multillm.cost_usd": record.get("cost_usd"),
            "multillm.cost_basis": record.get("cost_basis"),
            "enduser.id": record.get("principal"),
            "multillm.request_id": record.get("request_id"),
        }),
        "status": {"code": STATUS_ERROR} if (record.get("status") or 0) >= 500 else {},
    }
    if record.get("parent_span_id"):
        result["parentSpanId"] = record["parent_span_id"]
    return result


def metrics(batch: list[dict]) -> list[dict]:
    """Delta sums for the batch, grouped by route kind, model and status class."""
    start = str(min(record["start_ns"] for record in batch))
    now = str(time.time_ns())
    groups: dict[tuple, dict] = {}
    for record in batch:
        key = (record["kind"], record.get("selected_model") or record.get("requested_model") or "unknown",
               f"{(record.get('status') or 0) // 100}xx")
        totals = groups.setdefault(key, {"requests": 0, "cost": 0.0, "input": 0, "output": 0})
        totals["requests"] += 1
        totals["cost"] += record.get("cost_usd") or 0.0
        totals["input"] += record.get("input_tokens") or 0
        totals["output"] += record.get("output_tokens") or 0

    def points(value, extra=None, *, double=False):
        return [{"attributes": _attributes({"multillm.kind": kind, "gen_ai.response.model": model,
                                            "http.response.status_class": status, **(extra or {})}),
                 "startTimeUnixNano": start, "timeUnixNano": now,
                 **({"asDouble": float(value(totals))} if double else {"asInt": str(int(value(totals)))})}
                for (kind, model, status), totals in groups.items()]

    def total(name, unit, data_points):
        return {"name": name, "unit": unit, "sum": {"dataPoints": data_points, "aggregationTemporality": DELTA,
                                                    "isMonotonic": True}}

    return [
        total("multillm.requests", "{request}", points(lambda item: item["requests"])),
        total("multillm.cost", "USD", points(lambda item: item["cost"], double=True)),
        total("multillm.tokens", "{token}", points(lambda item: item["input"], {"gen_ai.token.type": "input"})
              + points(lambda item: item["output"], {"gen_ai.token.type": "output"})),
    ]


EXPORTER = TelemetryExporter()
