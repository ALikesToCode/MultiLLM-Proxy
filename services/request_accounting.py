"""Accounting for billable API requests: model allowlists, dollar budgets, the usage
ledger and telemetry.

The API auth decorators call `begin` after authentication and `finish` with the view's
response, so routes need no changes. Billable means a POST to chat, responses, images,
image batches, videos, embeddings, audio or a provider pass-through route; Knowledge has
its own ledger. A streamed response is recorded when it closes, with token usage read
from its final events when the provider reports it. No prompt, output or key is kept.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from flask import Response, current_app, g, jsonify, request
from werkzeug.exceptions import HTTPException

from error_handlers import APIError
from services import key_controls, telemetry_export, usage_ledger
from services.budget_service import BudgetService, budgeted
from services.cost_service import CostService

logger = logging.getLogger(__name__)

BILLABLE_PATHS = {
    "/v1/chat/completions": "chat",
    "/optimize/v1/chat/completions": "chat",
    "/intelligence/v1/chat/completions": "chat",
    "/v1/free/chat/completions": "chat",
    "/v1/responses": "responses",
    "/v1/messages": "chat",
    "/v1/images/generations": "images",
    "/v1/images/edits": "images",
    "/v1/images/batch": "images",
    "/v1/images/batches": "images",
    "/v1/videos": "videos",
    "/v1/embeddings": "embeddings",
    "/v1/audio/transcriptions": "audio",
    "/v1/audio/speech": "audio",
}
# Default models when a request omits one; they must match the routes' own defaults.
DEFAULT_MODELS = {
    "/v1/images/edits": "auto:image-edit",
    "/v1/embeddings": "auto:embed",
    "/v1/audio/speech": "auto:tts",
    "/v1/audio/transcriptions": "auto:stt",
}
# An asynchronous batch is admitted here, but its items are recorded when the Workflow
# runs them (see `admit_item` and `record_item`), so the submission itself is not.
DEFERRED_PATHS = frozenset({"/v1/images/batches"})
BATCH_PATHS = frozenset({"/v1/images/batch", "/v1/images/batches"})
FREE_MODE_PATH = re.compile(r"/v1/free/([A-Za-z0-9_-]{1,32})/chat/completions\Z")
PROXY_ENDPOINTS = frozenset({"proxy", "google_chat_completions"})
BILLABLE_METHODS = frozenset({"POST", "PUT", "PATCH"})
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")
ENDPOINT = re.compile(r"/[A-Za-z0-9._~:/@+-]{0,255}\Z")
REQUEST_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
DEFAULT_OUTPUT_TOKENS = 1024
MAX_USAGE_JSON_BYTES = 16 * 1024 * 1024
SSE_TAIL_BYTES = 65536


@dataclass
class UsageContext:
    kind: str
    models: list[str]
    provider: Optional[str]
    user: dict
    started: float
    start_ns: int
    input_tokens: int = 0
    output_tokens: int = 0
    units: int = 1
    estimate: float = 0.0
    reservation: Optional[str] = None
    trace: tuple = field(default_factory=tuple)
    # Captured from the request when the view returns, so a stream can be recorded
    # after the request context is gone.
    path: str = "/"
    method: str = "POST"
    request_id: Optional[str] = None
    selected: Optional[str] = None
    finished: bool = False
    # Served from the response cache: no provider was called, so nothing is charged.
    cached: bool = False


def classify() -> Optional[str]:
    if request.method not in BILLABLE_METHODS:
        return None
    if request.endpoint in PROXY_ENDPOINTS:
        return "proxy"
    if request.method == "POST":
        return BILLABLE_PATHS.get(request.path) or ("chat" if FREE_MODE_PATH.fullmatch(request.path) else None)
    return None


def _payload() -> Optional[dict]:
    """The JSON body, cached for the view; None when it is absent, invalid or too large,
    which the view then reports itself."""
    try:
        payload = request.get_json(silent=True) if request.is_json else None
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _batch_parts(body: dict) -> tuple[list, dict]:
    items = body.get("items")
    defaults = body.get("defaults")
    return (items if isinstance(items, list) else []), (defaults if isinstance(defaults, dict) else {})


def _requested_models(kind: str, payload: Optional[dict]) -> tuple[list[str], Optional[str]]:
    """Every model the request may use, and the provider namespace for pass-through."""
    body = payload or {}
    if kind == "proxy":
        provider = str((request.view_args or {}).get("api_provider") or request.path.strip("/").split("/", 1)[0])
        model = body.get("model")
        return ([f"{provider}:{model}"] if isinstance(model, str) and model.strip() else []), provider.lower()
    if request.path in ("/v1/audio/transcriptions", "/v1/images/edits") and not request.is_json:
        model = request.form.get("model") or DEFAULT_MODELS[request.path]
        return [model], None
    if request.path in BATCH_PATHS:
        items, defaults = _batch_parts(body)
        models = [item.get("model") or defaults.get("model") or "auto:image" for item in items if isinstance(item, dict)]
        return [model for model in dict.fromkeys(models) if isinstance(model, str)], None
    if request.path == "/v1/videos":
        video = body.get("model") or "auto:video"
        return ([video] if isinstance(video, str) else []), None
    free = FREE_MODE_PATH.fullmatch(request.path)
    if free:
        return [f"free:{free.group(1)}"], None
    model = body.get("model")
    if model is None and request.path in DEFAULT_MODELS:
        model = DEFAULT_MODELS[request.path]
    if model is None and request.path == "/v1/free/chat/completions":
        model = "free:text"
    elif model is None and (request.path.startswith("/intelligence/") or "routing" in body):
        model = "auto:intelligence"
    return ([model] if isinstance(model, str) and model else []), None


def _image_units(kind: str, payload: Optional[dict]) -> int:
    body = payload or {}
    if request.path in BATCH_PATHS:
        items, defaults = _batch_parts(body)
        count = 0
        for item in items:
            n = (item.get("n") if isinstance(item, dict) else None) or defaults.get("n") or 1
            count += n if isinstance(n, int) and n > 0 else 1
        return max(1, count)
    if request.path == "/v1/images/edits" and not request.is_json:
        try:
            n = int(request.form.get("n") or 1)
        except ValueError:
            n = 1
        return n if 0 < n <= 100 else 1
    if kind == "images":
        n = body.get("n", 1)
        return n if isinstance(n, int) and 0 < n <= 100 else 1
    return 1


def _token_estimates(payload: Optional[dict]) -> tuple[int, int]:
    """Input and reserved output tokens, as the rate limiter estimated them."""
    limits = getattr(g, "rate_limit", None) or {}
    if isinstance(limits.get("input_tokens"), int):
        return limits["input_tokens"], int(limits.get("output_tokens") or 0)
    from services.rate_limit_service import RateLimitService  # noqa: PLC0415

    input_tokens = RateLimitService.estimate_input_tokens(payload)
    try:
        output_tokens = RateLimitService.requested_output_tokens(payload)
    except ValueError:
        output_tokens = None
    if output_tokens is None:
        output_tokens = DEFAULT_OUTPUT_TOKENS if payload and any(
            key in payload for key in ("messages", "input", "prompt", "contents")) else 0
    return input_tokens, output_tokens


def _candidates(model: str) -> list[str]:
    if model.startswith("auto:"):
        try:
            from services.auto_route_service import AutoRouteService  # noqa: PLC0415

            route = AutoRouteService.get_route(model)
            if route is not None:
                return list(route.candidates)
        except Exception:
            return [model]
    return [model]


def price(models: list[str], input_tokens: int, output_tokens: int, units: int) -> Optional[float]:
    """The highest configured price among the models (and automatic route candidates)
    a request may use, in USD; None when none of them is priced."""
    costs = [CostService.estimate(candidate, input_tokens, output_tokens, requests=units)
             for model in models for candidate in _candidates(model)]
    known = [cost for cost in costs if cost is not None]
    return max(known) if known else None


def estimate_cost(models: list[str], input_tokens: int, output_tokens: int, units: int) -> float:
    return price(models, input_tokens, output_tokens, units) or 0.0


def _error(status: int, code: str, message: str, retry_after: Optional[int] = None, **extra) -> Response:
    response = jsonify({"error": code, "message": message, **extra})
    response.status_code = status
    if retry_after:
        response.headers["Retry-After"] = str(retry_after)
    return response


def check_key_controls(user: dict) -> Optional[Response]:
    """Expiry and client address checks for every authenticated API request."""
    if key_controls.expired(user):
        return _error(401, "key_expired",
                      f"This API key expired at {user.get('expires_at')}. Ask an administrator for a new expiry or key.")
    if not key_controls.ip_allowed(user, key_controls.client_ip(request)):
        return _error(403, "ip_not_allowed", "This API key cannot be used from this client address.")
    return None


def begin() -> Optional[Response]:
    """Enforce the model allowlist and budget before dispatch; None admits the request."""
    kind = classify()
    user = getattr(g, "authenticated_user", None)
    if kind is None or not isinstance(user, dict):
        return None
    payload = _payload()
    models, provider = _requested_models(kind, payload)
    for model in models:
        if not key_controls.model_allowed(user, model):
            return _error(403, "model_not_allowed",
                          f"This API key is not allowed to use {str(model)[:128]}.", model=str(model)[:256])
    if kind == "proxy" and not models and provider and not key_controls.provider_allowed(user, provider):
        return _error(403, "model_not_allowed",
                      f"This API key is not allowed to call the {provider[:64]} provider directly.")
    context = UsageContext(kind=kind, models=models, provider=provider, user=user,
                           started=getattr(g, "request_started_at", None) or time.perf_counter(),
                           start_ns=time.time_ns(), units=_image_units(kind, payload),
                           trace=telemetry_export.trace_context(request.headers.get("traceparent")))
    context.input_tokens, context.output_tokens = _token_estimates(payload)
    if budgeted(user):
        context.estimate = estimate_cost([_qualified(model, provider) for model in models],
                                         context.input_tokens, context.output_tokens, context.units)
        decision = BudgetService.check_and_reserve(user, context.estimate)
        if not decision.allowed:
            return _error(decision.status_code, decision.error, decision.message, decision.retry_after,
                          **({"budget": decision.details} if decision.details else {}))
        context.reservation = decision.reservation
    g.usage_context = context
    return None


def _qualified(model: str, provider: Optional[str]) -> str:
    return model if ":" in model or not provider else f"{provider}:{model}"


def _usage_from(value: Any) -> Optional[tuple[int, int]]:
    """Input and output tokens from a Chat Completions, Responses or embeddings body."""
    if not isinstance(value, dict):
        return None
    usage = value.get("usage")
    if not isinstance(usage, dict) and isinstance(value.get("response"), dict):
        usage = value["response"].get("usage")
    if not isinstance(usage, dict):
        return None
    input_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
    output_tokens = usage.get("completion_tokens", usage.get("output_tokens", 0))
    if type(input_tokens) is not int or type(output_tokens) is not int or input_tokens < 0 or output_tokens < 0:
        return None
    return input_tokens, output_tokens


def _sse_usage(tail: bytes) -> Optional[tuple[int, int]]:
    for line in reversed(tail.decode("utf-8", "replace").splitlines()):
        line = line.strip()
        if not line.startswith("data:") or '"usage"' not in line:
            continue
        try:
            found = _usage_from(json.loads(line[5:].strip()))
        except (ValueError, RecursionError):
            continue
        if found:
            return found
    return None


def _json_tail_usage(tail: bytes) -> Optional[tuple[int, int]]:
    """Token usage from the last `"usage": {...}` object in a streamed JSON body's tail."""
    text = tail.decode("utf-8", "replace")
    position = text.rfind('"usage"')
    start = text.find("{", position) if position >= 0 else -1
    if start < 0:
        return None
    depth, quoted, escaped = 0, False, False
    for index in range(start, len(text)):
        character = text[index]
        if quoted:
            escaped, quoted = (False, True) if escaped else (character == "\\", character != '"')
        elif character == '"':
            quoted = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                try:
                    return _usage_from({"usage": json.loads(text[start:index + 1])})
                except (ValueError, RecursionError):
                    return None
    return None


def _json_body(response: Response) -> Any:
    if response.is_streamed or response.direct_passthrough or response.mimetype != "application/json":
        return None
    try:
        data = response.get_data()
        return json.loads(data) if len(data) <= MAX_USAGE_JSON_BYTES else None
    except (ValueError, RecursionError, RuntimeError):
        return None


def _image_count(body: Any) -> Optional[int]:
    if not isinstance(body, dict):
        return None
    if isinstance(body.get("summary"), dict) and type(body["summary"].get("images")) is int:
        return body["summary"]["images"]
    return len(body["data"]) if isinstance(body.get("data"), list) else None


def _clean_model(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and MODEL_ID.fullmatch(value) else None


def _record(context: UsageContext, status: int, usage: Optional[tuple[int, int]], units: Optional[int]) -> None:
    if context.finished:
        return
    context.finished = True
    if context.path in DEFERRED_PATHS:
        BudgetService.settle(context.reservation)
        return
    try:
        row = _row(context, status, usage, units)
        BudgetService.record_cost(row)
        usage_ledger.LEDGER.record(row)
        telemetry_export.EXPORTER.submit({**row, "method": context.method, "trace_id": context.trace[0],
                                          "parent_span_id": context.trace[1], "start_ns": context.start_ns,
                                          "end_ns": time.time_ns()})
    except Exception as error:  # Accounting must never fail a served request.
        logger.warning("Usage could not be recorded (%s)", type(error).__name__)
    finally:
        # The settled cost is counted before the in-flight estimate is released.
        BudgetService.settle(context.reservation)


def _row(context: UsageContext, status: int, usage: Optional[tuple[int, int]], units: Optional[int]) -> dict:
    qualified = [_qualified(model, context.provider) for model in context.models]
    requested = qualified[0] if len(qualified) == 1 else ("mixed" if qualified else None)
    selected = context.selected or (requested if requested and requested != "mixed"
                                    and not requested.startswith(("auto:", "free:")) else None)
    if units is not None:
        context.units = units
    cost, basis = None, None
    if context.cached and status < 400:
        cost, basis = 0.0, "cache"
    elif status < 400 or usage:
        if usage:
            input_tokens, output_tokens, basis = usage[0], usage[1], "usage"
        else:
            input_tokens, output_tokens, basis = context.input_tokens, context.output_tokens, "estimate"
        cost = price([selected] if selected else qualified, input_tokens, output_tokens, context.units)
        basis = basis if cost is not None else None
    prefix = context.user.get("api_key_prefix")
    return {
        "at": usage_ledger.utc_timestamp(),
        "principal": str(context.user.get("username") or context.user.get("id") or "unknown")[:256],
        "key_prefix": str(prefix)[:64] if prefix else None,
        "kind": context.kind,
        "endpoint": context.path if ENDPOINT.fullmatch(context.path) else f"/{context.kind}",
        "requested_model": _clean_model(requested),
        "selected_model": _clean_model(selected),
        "status": min(599, max(100, int(status))),
        "latency_ms": min(86_400_000, max(0, round((time.perf_counter() - context.started) * 1000))),
        "input_tokens": usage[0] if usage else None,
        "output_tokens": usage[1] if usage else None,
        "cost_usd": cost,
        "cost_basis": basis,
        "request_id": context.request_id,
    }


def _capture(context: UsageContext) -> None:
    g.usage_context = None
    context.path = request.path
    context.method = request.method
    request_id = getattr(g, "request_id", None)
    context.request_id = request_id if isinstance(request_id, str) and REQUEST_ID.fullmatch(request_id) else None
    selected = getattr(g, "multillm_model", None)
    context.selected = selected if isinstance(selected, str) else None


class _SniffedStream:
    """Pass a streamed body through unchanged while keeping its tail for token usage."""

    def __init__(self, iterable: Iterable, on_close) -> None:
        self._iterable = iterable
        self._iterator = iter(iterable)
        self._on_close = on_close
        self._tail = b""

    def __iter__(self):
        return self

    def __next__(self):
        chunk = next(self._iterator)
        data = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
        self._tail = (self._tail + data)[-SSE_TAIL_BYTES:]
        return chunk

    def close(self):
        try:
            close = getattr(self._iterable, "close", None)
            if close is not None:
                close()
        finally:
            on_close, self._on_close = self._on_close, None
            if on_close is not None:
                on_close(self._tail)


def finish(result: Any) -> Any:
    """Record the request once its response is known; streams are recorded on close."""
    context = getattr(g, "usage_context", None)
    if not isinstance(context, UsageContext):
        return result
    _capture(context)
    try:
        response = current_app.make_response(result)
    except Exception:
        _record(context, 500, None, None)
        return result
    context.cached = response.headers.get("X-MultiLLM-Cache") == "hit"
    if response.is_streamed:
        event_stream = (response.mimetype or "") == "text/event-stream"
        json_stream = (response.mimetype or "").endswith("json")
        status = response.status_code

        def closed(tail: bytes) -> None:
            usage = _sse_usage(tail) if event_stream else _json_tail_usage(tail) if json_stream else None
            _record(context, status, usage, None)

        response.response = _SniffedStream(response.response, closed)
        return response
    body = _json_body(response)
    _record(context, response.status_code, _usage_from(body),
            _image_count(body) if context.kind == "images" and response.status_code < 400 else None)
    return response


def fail(error: BaseException) -> None:
    """Record a view that raised; Flask's error handlers still build the response."""
    context = getattr(g, "usage_context", None)
    if not isinstance(context, UsageContext):
        return
    _capture(context)
    if isinstance(error, APIError):
        status = error.status_code
    elif isinstance(error, HTTPException):
        status = error.code or 500
    else:
        status = 500
    _record(context, status, None, None)


def admit_item(user: dict, model: str, units: int) -> tuple[Optional[dict], Optional[str]]:
    """Allowlist and budget for work run later for an account, such as an asynchronous
    batch item. Returns an error for the item, or the budget reservation to settle."""
    if not key_controls.model_allowed(user, model):
        return {"status": 403, "code": "model_not_allowed",
                "message": f"This API key is not allowed to use {str(model)[:128]}."}, None
    if not budgeted(user):
        return None, None
    decision = BudgetService.check_and_reserve(user, estimate_cost([model], 0, 0, max(1, units)))
    if not decision.allowed:
        return {"status": decision.status_code, "code": decision.error, "message": decision.message}, None
    return None, decision.reservation


def record_item(user: dict, *, endpoint: str, requested: str, selected: Optional[str], status: int,
                units: int, started: float, reservation: Optional[str]) -> None:
    """Record one item of background work in the ledger and settle its reservation."""
    context = UsageContext(kind="images", models=[requested], provider=None, user=user, started=started,
                           start_ns=time.time_ns(), units=max(1, units), reservation=reservation)
    context.path, context.selected = endpoint, selected
    _record_row(context, status, units)


def _record_row(context: UsageContext, status: int, units: int) -> None:
    try:
        row = _row(context, status, None, units)
        BudgetService.record_cost(row)
        usage_ledger.LEDGER.record(row)
    except Exception as error:  # Accounting must never fail the work it describes.
        logger.warning("Usage could not be recorded (%s)", type(error).__name__)
    finally:
        BudgetService.settle(context.reservation)
