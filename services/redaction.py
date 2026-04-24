from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

SENSITIVE_HEADERS = {
    "authorization",
    "api-key",
    "x-api-key",
    "x-goog-api-key",
    "cookie",
    "set-cookie",
}

SENSITIVE_JSON_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "content",
    "input",
    "messages",
    "output",
    "password",
    "prompt",
    "secret",
    "text",
    "token",
}

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "key",
    "token",
}

REDACTED = "<redacted>"
MAX_STRING_LENGTH = 256
SECRET_TEXT_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{12,}"),
    re.compile(r'("(?:api[_-]?key|authorization|token|secret)"\s*:\s*")[^"]+(")', re.IGNORECASE),
    re.compile(r"((?:api[_-]?key|authorization|token|secret|key)=)[^&\s]+", re.IGNORECASE),
]


def _is_sensitive_key(key: Any, sensitive_keys: set[str]) -> bool:
    key_text = str(key).lower().replace("-", "_")
    return key_text in sensitive_keys


def redact_text(value: Any) -> str:
    text = str(value)
    for pattern in SECRET_TEXT_PATTERNS:
        if pattern.groups >= 2:
            text = pattern.sub(rf"\1{REDACTED}\2", text)
        elif pattern.groups == 1:
            text = pattern.sub(rf"\1{REDACTED}", text)
        else:
            text = pattern.sub(REDACTED, text)
    if len(text) <= MAX_STRING_LENGTH:
        return text
    return f"{text[:MAX_STRING_LENGTH]}...<truncated>"


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, Any]:
    if not headers:
        return {}
    return {
        str(key): REDACTED if str(key).lower() in SENSITIVE_HEADERS else value
        for key, value in dict(headers).items()
    }


def redact_query_params(params: Any) -> dict[str, Any]:
    if not params:
        return {}

    if hasattr(params, "items"):
        items = params.items()
    else:
        items = params

    redacted = {}
    for key, value in items:
        redacted[str(key)] = REDACTED if _is_sensitive_key(key, SENSITIVE_QUERY_KEYS) else value
    return redacted


def redact_payload(value: Any, *, _depth: int = 0) -> Any:
    if _depth > 8:
        return "<max-depth>"

    if isinstance(value, Mapping):
        redacted = {}
        for key, item in value.items():
            if _is_sensitive_key(key, SENSITIVE_JSON_KEYS):
                redacted[key] = REDACTED
            else:
                redacted[key] = redact_payload(item, _depth=_depth + 1)
        return redacted

    if isinstance(value, list):
        return [redact_payload(item, _depth=_depth + 1) for item in value]

    if isinstance(value, tuple):
        return tuple(redact_payload(item, _depth=_depth + 1) for item in value)

    if isinstance(value, str):
        return redact_text(value)

    return value
