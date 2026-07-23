from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional


OPENCODE_GO_REQUEST_HEADER_WHITELIST = {
    "anthropic-beta": "Anthropic-Beta",
    "anthropic-dangerous-direct-browser-access": "Anthropic-Dangerous-Direct-Browser-Access",
    "anthropic-version": "Anthropic-Version",
    "idempotency-key": "Idempotency-Key",
    "openai-beta": "OpenAI-Beta",
    "openai-organization": "OpenAI-Organization",
    "openai-project": "OpenAI-Project",
    "x-client-request-id": "X-Client-Request-ID",
}

OPENCODE_GO_ENDPOINTS = frozenset(
    {
        ("POST", "v1/chat/completions"),
        ("POST", "v1/messages"),
        ("GET", "v1/models"),
    }
)


def _header_value(headers: Mapping[str, Any], name: str) -> Optional[str]:
    direct_value = headers.get(name)
    if direct_value is not None:
        return str(direct_value)

    normalized_name = name.lower()
    for header, value in headers.items():
        if str(header).lower() == normalized_name:
            return str(value)
    return None


def normalized_opencode_go_path(path: str) -> str:
    return path.strip("/")


def canonical_opencode_go_path(path: str) -> str:
    normalized_path = normalized_opencode_go_path(path)
    if not normalized_path:
        return "v1"
    if normalized_path.lower() == "v1":
        return "v1"
    if normalized_path.lower().startswith("v1/"):
        return f"v1/{normalized_path[3:]}"
    return f"v1/{normalized_path}"


def build_opencode_go_url(base_url: str, path: str) -> str:
    canonical_path = canonical_opencode_go_path(path)
    normalized_base_url = base_url.rstrip("/")

    if normalized_base_url.lower().endswith("/v1"):
        suffix = canonical_path[3:] if canonical_path.lower().startswith("v1/") else ""
    else:
        suffix = canonical_path

    return (
        f"{normalized_base_url}/{suffix}"
        if suffix
        else normalized_base_url
    )


def is_opencode_go_documented_request(path: str, method: str) -> bool:
    return (
        method.upper(),
        canonical_opencode_go_path(path).lower(),
    ) in OPENCODE_GO_ENDPOINTS


def is_opencode_go_anthropic_request(path: str) -> bool:
    return canonical_opencode_go_path(path).lower() == "v1/messages"


def is_opencode_go_native_path(path: str) -> bool:
    canonical_path = canonical_opencode_go_path(path).lower()
    if canonical_path not in {endpoint_path for _, endpoint_path in OPENCODE_GO_ENDPOINTS}:
        return False
    return normalized_opencode_go_path(path).lower() != "chat/completions"


def is_opencode_go_native_request(path: str, method: str) -> bool:
    """Use raw transport for documented routes without changing the legacy chat path."""
    return (
        is_opencode_go_documented_request(path, method)
        and is_opencode_go_native_path(path)
    )


def opencode_go_caller_authorization(
    headers: Mapping[str, Any],
) -> Optional[str]:
    proxy_api_key = _header_value(headers, "X-MultiLLM-Api-Key")
    authorization = _header_value(headers, "Authorization")
    if not proxy_api_key or not authorization:
        return None
    scheme, separator, credentials = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credentials.strip():
        return None
    return f"{scheme} {credentials.strip()}"


def opencode_go_caller_api_key(
    headers: Mapping[str, Any],
) -> Optional[str]:
    proxy_api_key = _header_value(headers, "X-MultiLLM-Api-Key")
    upstream_api_key = _header_value(headers, "X-Api-Key")
    if not proxy_api_key or not upstream_api_key or not upstream_api_key.strip():
        return None
    return upstream_api_key.strip()


def opencode_go_has_caller_auth(headers: Mapping[str, Any]) -> bool:
    return bool(
        opencode_go_caller_authorization(headers)
        or opencode_go_caller_api_key(headers)
    )
