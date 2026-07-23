from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional


NAVYAI_REQUEST_HEADER_WHITELIST = {
    "anthropic-beta": "Anthropic-Beta",
    "anthropic-dangerous-direct-browser-access": "Anthropic-Dangerous-Direct-Browser-Access",
    "anthropic-version": "Anthropic-Version",
    "idempotency-key": "Idempotency-Key",
    "openai-beta": "OpenAI-Beta",
    "openai-organization": "OpenAI-Organization",
    "openai-project": "OpenAI-Project",
    "x-client-request-id": "X-Client-Request-ID",
}

NAVYAI_PUBLIC_ENDPOINTS = frozenset(
    {
        ("GET", "v1/models"),
        ("GET", "v1/models/status"),
        ("POST", "v1/oauth/revoke"),
        ("POST", "v1/oauth/token"),
    }
)
NAVYAI_INTERACTIVE_OAUTH_ENDPOINT = ("GET", "v1/oauth/authorize")


def _header_value(headers: Mapping[str, Any], name: str) -> Optional[str]:
    direct_value = headers.get(name)
    if direct_value is not None:
        return str(direct_value)

    normalized_name = name.lower()
    for header, value in headers.items():
        if str(header).lower() == normalized_name:
            return str(value)
    return None


def normalized_navyai_path(path: str) -> str:
    return path.strip("/")


def is_navyai_public_request(path: str, method: str) -> bool:
    return (
        method.upper(),
        normalized_navyai_path(path).lower(),
    ) in NAVYAI_PUBLIC_ENDPOINTS


def is_navyai_interactive_oauth_request(path: str, method: str) -> bool:
    return (
        method.upper(),
        normalized_navyai_path(path).lower(),
    ) == NAVYAI_INTERACTIVE_OAUTH_ENDPOINT


def navyai_caller_authorization(
    headers: Mapping[str, Any],
) -> Optional[str]:
    proxy_api_key = _header_value(headers, "X-MultiLLM-Api-Key")
    authorization = _header_value(headers, "Authorization")
    if not proxy_api_key or not authorization:
        return None
    scheme, separator, credentials = authorization.partition(" ")
    if not separator or scheme.lower() not in {"basic", "bearer"}:
        return None
    if not credentials.strip():
        return None
    return f"{scheme} {credentials.strip()}"


def navyai_caller_api_key(
    headers: Mapping[str, Any],
) -> Optional[str]:
    proxy_api_key = _header_value(headers, "X-MultiLLM-Api-Key")
    upstream_api_key = _header_value(headers, "X-Api-Key")
    if not proxy_api_key or not upstream_api_key or not upstream_api_key.strip():
        return None
    return upstream_api_key.strip()


def navyai_has_caller_auth(headers: Mapping[str, Any]) -> bool:
    return bool(
        navyai_caller_authorization(headers)
        or navyai_caller_api_key(headers)
    )
