"""Exact-match response cache for deterministic, non-streaming Chat Completions.

A caller opts in per request with `X-MultiLLM-Cache: on`. A stored answer is replayed only
to the same API key for a byte-identical request body (compared after canonical JSON
encoding), and only after the route's authentication, scope and rate checks have passed.
Eligible requests are non-streaming, single-choice and deterministic (`temperature` 0 or an
integer `seed`) and offer no tools the client could run again. Only complete successful
answers are stored: errors, truncated or filtered answers and tool calls never are. The
store is Container memory, bounded by entry count, bytes and TTL, and lost on sleep.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from functools import wraps

from flask import Response, g, request

from route_helpers import request_api_key
from services.cache_service import ResponseCache

CACHE_HEADER = "X-MultiLLM-Cache"
_OPT_IN = frozenset({"on", "true", "1", "yes"})
_REFRESH = "refresh"
_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*(\d{1,9})\s*(?:,|$)")
# Headers describing how the stored answer was produced, replayed with it.
_STORED_HEADERS = (
    "X-MultiLLM-Auto-Route", "X-MultiLLM-Auto-Selected-Model", "X-MultiLLM-Auto-Selected-Priority",
    "X-MultiLLM-Auto-Ordering", "X-MultiLLM-Prompt-Cache", "X-MultiLLM-Prompt-Cache-Mode",
)
_COMPLETE_FINISH_REASONS = frozenset({"stop", "end_turn", "stop_sequence", "eos"})
_EXCLUDED_MODELS = frozenset({"auto:intelligence"})

_store = ResponseCache()


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def _settings() -> dict:
    return {
        "enabled": os.environ.get("RESPONSE_CACHE_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"},
        "ttl": _env_int("RESPONSE_CACHE_TTL_SECONDS", 300, 1, 86_400),
        "max_entries": _env_int("RESPONSE_CACHE_MAX_ENTRIES", 512, 1, 10_000),
        "max_bytes": _env_int("RESPONSE_CACHE_MAX_BYTES", 16 * 1024 * 1024, 64 * 1024, 256 * 1024 * 1024),
    }


def request_mode() -> tuple[str | None, int | None]:
    """(None | "on" | "refresh", max_age) from the opt-in header and Cache-Control."""
    opt_in = request.headers.get(CACHE_HEADER, "").strip().lower()
    mode = "on" if opt_in in _OPT_IN else _REFRESH if opt_in == _REFRESH else None
    if mode is None:
        return None, None
    directives = request.headers.get("Cache-Control", "").lower()
    if "no-store" in directives:
        return None, None
    if "no-cache" in directives:
        mode = _REFRESH
    match = _MAX_AGE.search(directives)
    return mode, int(match.group(1)) if match else None


def request_is_cacheable(payload: object) -> bool:
    """Deterministic, non-streaming, single-choice requests that offer no runnable tools."""
    if not isinstance(payload, dict) or payload.get("stream"):
        return False
    model = payload.get("model")
    if not isinstance(model, str) or model in _EXCLUDED_MODELS or "routing" in payload:
        return False
    if payload.get("n", 1) != 1:
        return False
    if (payload.get("tools") or payload.get("functions")) and payload.get("tool_choice") != "none":
        return False
    temperature, seed = payload.get("temperature"), payload.get("seed")
    zero_temperature = type(temperature) in (int, float) and temperature == 0
    return zero_temperature or type(seed) is int


def _complete_answer(body: bytes) -> bool:
    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(parsed, dict) or "error" in parsed:
        return False
    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        return False
    for choice in choices:
        if not isinstance(choice, dict) or choice.get("finish_reason") not in _COMPLETE_FINISH_REASONS:
            return False
        message = choice.get("message")
        if not isinstance(message, dict) or message.get("tool_calls") or message.get("function_call"):
            return False
    return True


def _principal() -> str | None:
    """The authenticated user and a digest of the presented key; entries never cross keys."""
    user = getattr(g, "authenticated_user", None) or {}
    api_key = request_api_key()
    name = user.get("username") or user.get("id")
    if not api_key or not name:
        return None
    key_digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    return f"{name}\x00{key_digest}"


def cache_key(principal: str, path: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256("\x00".join((principal, path, canonical)).encode("utf-8")).hexdigest()


def _hit(entry) -> Response:
    body, metadata, age = entry
    response = Response(body, status=200, content_type=metadata["content_type"])
    for name, value in metadata["headers"].items():
        response.headers[name] = value
    response.headers[CACHE_HEADER] = "hit"
    response.headers["Age"] = str(int(age))
    if metadata.get("provider"):
        g.multillm_provider = metadata["provider"]
    if metadata.get("model"):
        g.multillm_model = metadata["model"]
    g.multillm_route_decision = "cache-hit"
    return response


def _store_if_complete(response: Response, key: str, settings: dict) -> None:
    if (response.status_code != 200 or response.direct_passthrough
            or response.mimetype != "application/json"):
        return
    body = response.get_data()
    if len(body) > settings["max_bytes"] // 8 or not _complete_answer(body):
        return
    _store.configure(max_entries=settings["max_entries"], max_bytes=settings["max_bytes"])
    _store.put(key, body, {
        "content_type": response.headers.get("Content-Type", "application/json"),
        "headers": {name: response.headers[name] for name in _STORED_HEADERS if name in response.headers},
        "provider": getattr(g, "multillm_provider", None),
        "model": getattr(g, "multillm_model", None),
    }, ttl_seconds=settings["ttl"])


def _mark(response, value: str):
    if isinstance(response, Response):
        response.headers[CACHE_HEADER] = value
    return response


def cached_chat_completion(view):
    """Wrap an authenticated Chat Completions view; apply it below the auth decorator."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        mode, max_age = request_mode()
        settings = _settings()
        if mode is None or request.method != "POST":
            return view(*args, **kwargs)
        payload = request.get_json(silent=True)
        principal = _principal()
        if not settings["enabled"] or principal is None or not request_is_cacheable(payload):
            return _mark(view(*args, **kwargs), "bypass")
        key = cache_key(principal, request.path, payload)
        if mode == "on":
            entry = _store.get(key, max_age=max_age)
            if entry is not None:
                return _hit(entry)
        response = view(*args, **kwargs)
        if isinstance(response, Response):
            _store_if_complete(response, key, settings)
        return _mark(response, "miss")

    return wrapper


def clear() -> None:
    _store.clear()
