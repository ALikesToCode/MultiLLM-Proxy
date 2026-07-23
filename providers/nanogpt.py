from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional


NANOGPT_REQUEST_HEADER_WHITELIST = {
    "anthropic-beta": "anthropic-beta",
    "anthropic-dangerous-direct-browser-access": "Anthropic-Dangerous-Direct-Browser-Access",
    "anthropic-version": "Anthropic-Version",
    "idempotency-key": "Idempotency-Key",
    "memory": "memory",
    "memory-expiration-days": "memory_expiration_days",
    "memory_expiration_days": "memory_expiration_days",
    "moderation": "moderation",
    "moderation-model": "moderation-model",
    "openai-beta": "OpenAI-Beta",
    "redaction": "redaction",
    "x-app-name": "X-App-Name",
    "x-billing-mode": "X-Billing-Mode",
    "x-byok-provider": "X-BYOK-Provider",
    "x-client-request-id": "X-Client-Request-ID",
    "x-encryption-key": "X-Encryption-Key",
    "x-encryption-passphrase": "X-Encryption-Passphrase",
    "x-fal-object-lifecycle-preference": "X-Fal-Object-Lifecycle-Preference",
    "x-payment": "X-PAYMENT",
    "x-prompt-caching-cut-after": "X-Prompt-Caching-Cut-After",
    "x-provider": "X-Provider",
    "x-team-id": "X-Team-ID",
    "x-use-byok": "x-use-byok",
    "x-x402": "x-x402",
}

NANOGPT_OPTIONAL_AUTH_GET_PATHS = frozenset(
    {
        "explore/search",
        "explore/text-models",
        "get-fiat-prices",
        "get-nano-price",
        "v1/audio-models",
        "v1/character-models",
        "v1/embedding-models",
        "v1/image-models",
        "v1/images/models",
        "v1/models",
        "v1/moderation-models",
        "v1/video-models",
    }
)

NANOGPT_PUBLIC_X402_PATHS = frozenset({"v1/x402/endpoints"})
NANOGPT_PUBLIC_X402_PREFIXES = ("x402/complete/", "x402/status/")
NANOGPT_BATCH_PREFIXES = ("v1/batches", "v1/files")
NANOGPT_ORIGIN_PATHS = frozenset(
    {
        ".well-known/oauth-authorization-server",
        ".well-known/oauth-protected-resource",
        "auth.md",
        "oauth/register",
        "oauth/token",
    }
)
NANOGPT_PUBLIC_REQUESTS = frozenset(
    {
        ("GET", ".well-known/oauth-authorization-server"),
        ("GET", ".well-known/oauth-protected-resource"),
        ("GET", "auth.md"),
        ("POST", "oauth/register"),
        ("POST", "oauth/token"),
    }
)
NANOGPT_INTERACTIVE_BROWSER_REQUESTS = frozenset(
    {
        ("GET", "auth"),
        ("GET", "cli-login/verify"),
        ("GET", "oauth/authorize"),
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


def normalized_nanogpt_path(path: str) -> str:
    return path.strip("/")


def is_nanogpt_batch_path(path: str) -> bool:
    normalized_path = normalized_nanogpt_path(path)
    return any(
        normalized_path == prefix or normalized_path.startswith(f"{prefix}/")
        for prefix in NANOGPT_BATCH_PREFIXES
    )


def is_nanogpt_origin_path(path: str) -> bool:
    return normalized_nanogpt_path(path).lower() in NANOGPT_ORIGIN_PATHS


def build_nanogpt_url(
    base_url: str,
    batch_base_url: str,
    path: str,
    origin_base_url: str = "https://nano-gpt.com",
) -> str:
    normalized_path = normalized_nanogpt_path(path)
    if is_nanogpt_batch_path(normalized_path):
        batch_path = normalized_path.removeprefix("v1/")
        return f"{batch_base_url.rstrip('/')}/{batch_path}"
    if is_nanogpt_origin_path(normalized_path):
        return f"{origin_base_url.rstrip('/')}/{normalized_path}"
    if not normalized_path:
        return base_url.rstrip("/")
    return f"{base_url.rstrip('/')}/{normalized_path}"


def nanogpt_l402_authorization(
    headers: Mapping[str, Any],
) -> Optional[str]:
    authorization = _header_value(headers, "Authorization")
    if not authorization:
        return None
    scheme, separator, credentials = authorization.partition(" ")
    if not separator or scheme.lower() != "l402" or not credentials.strip():
        return None
    return f"L402 {credentials.strip()}"


def nanogpt_caller_authorization(
    headers: Mapping[str, Any],
) -> Optional[str]:
    proxy_api_key = _header_value(headers, "X-MultiLLM-Api-Key")
    authorization = _header_value(headers, "Authorization")
    if not proxy_api_key or not authorization:
        return None
    scheme, separator, credentials = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credentials.strip():
        return None
    return f"Bearer {credentials.strip()}"


def nanogpt_caller_api_key(
    headers: Mapping[str, Any],
) -> Optional[str]:
    proxy_api_key = _header_value(headers, "X-MultiLLM-Api-Key")
    upstream_api_key = _header_value(headers, "X-Api-Key")
    if not proxy_api_key or not upstream_api_key or not upstream_api_key.strip():
        return None
    return upstream_api_key.strip()


def nanogpt_has_caller_auth(headers: Mapping[str, Any]) -> bool:
    return bool(
        nanogpt_caller_authorization(headers)
        or nanogpt_caller_api_key(headers)
        or nanogpt_l402_authorization(headers)
    )


def is_nanogpt_public_request(path: str, method: str) -> bool:
    return (
        method.upper(),
        normalized_nanogpt_path(path).lower(),
    ) in NANOGPT_PUBLIC_REQUESTS


def is_nanogpt_interactive_browser_request(path: str, method: str) -> bool:
    return (
        method.upper(),
        normalized_nanogpt_path(path).lower(),
    ) in NANOGPT_INTERACTIVE_BROWSER_REQUESTS


def is_nanogpt_accountless_request(
    headers: Mapping[str, Any],
    path: str,
) -> bool:
    normalized_path = normalized_nanogpt_path(path).lower()
    if normalized_path in NANOGPT_PUBLIC_X402_PATHS:
        return True
    if any(normalized_path.startswith(prefix) for prefix in NANOGPT_PUBLIC_X402_PREFIXES):
        return True

    x402_value = _header_value(headers, "x-x402")
    if x402_value and x402_value.strip().lower() == "true":
        return True
    if _header_value(headers, "X-PAYMENT"):
        return True
    return nanogpt_l402_authorization(headers) is not None


def nanogpt_allows_missing_api_key(
    headers: Mapping[str, Any],
    path: str,
    method: str,
) -> bool:
    if is_nanogpt_public_request(path, method):
        return True
    if is_nanogpt_accountless_request(headers, path):
        return True
    if method.upper() != "GET":
        return False

    normalized_path = normalized_nanogpt_path(path).lower()
    if normalized_path in NANOGPT_OPTIONAL_AUTH_GET_PATHS:
        return True
    return normalized_path.startswith("v1/images/models/")
