from __future__ import annotations

import json
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
NANOGPT_SUBSCRIPTION_PAYLOAD_FIELDS = frozenset(
    {"billing_mode", "caching", "provider"}
)
NANOGPT_SUBSCRIPTION_PAYGO_HEADERS = frozenset(
    {
        "x-billing-mode",
        "x-byok-provider",
        "x-provider",
        "x-use-byok",
    }
)

# NanoGPT selects a provider from a `:<suffix>` on the model id. These routes
# leave subscription coverage and bill pay-as-you-go plus a provider-selection
# markup, so they are opt-in through NANOGPT_SPEED_ROUTING.
NANOGPT_SPEED_ROUTING_SUFFIXES = frozenset({"fast", "latency", "throughput"})


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


def nanogpt_speed_routing(config: Mapping[str, Any]) -> str:
    """Return the configured provider-selection suffix, or "" when disabled."""
    suffix = str(config.get("NANOGPT_SPEED_ROUTING") or "").strip().lower()
    return suffix if suffix in NANOGPT_SPEED_ROUTING_SUFFIXES else ""


def nanogpt_subscription_only(config: Mapping[str, Any]) -> bool:
    if nanogpt_speed_routing(config):
        # Provider selection is pay-as-you-go, so subscription-only guards
        # would strip fields the caller is now entitled to send.
        return False
    return str(config.get("NANOGPT_BILLING_MODE") or "").lower() == "subscription"


def nanogpt_text_base_url(
    standard_base_url: str,
    subscription_base_url: str,
    billing_mode: str,
    speed_routing: str,
) -> str:
    """Pick the text endpoint, since speed routing is pay-as-you-go only."""
    if speed_routing:
        return standard_base_url
    if str(billing_mode or "").strip().lower() == "subscription":
        return subscription_base_url
    return standard_base_url


def nanogpt_model_has_speed_suffix(model: Any) -> bool:
    if not isinstance(model, str) or ":" not in model:
        return False
    return model.rsplit(":", 1)[-1].strip().lower() in NANOGPT_SPEED_ROUTING_SUFFIXES


def nanogpt_speed_routing_conflicts(
    payload: Mapping[str, Any],
    headers: Optional[Mapping[str, Any]] = None,
) -> bool:
    """True when the caller already pinned a provider for this request."""
    if payload.get("provider"):
        return True
    if headers is None:
        return False
    for header in NANOGPT_SUBSCRIPTION_PAYGO_HEADERS:
        value = _header_value(headers, header)
        if value and value.strip():
            return True
    return False


def apply_nanogpt_speed_suffix(model: Any, suffix: str) -> Any:
    if not suffix or not isinstance(model, str) or not model.strip():
        return model
    if nanogpt_model_has_speed_suffix(model):
        return model
    return f"{model}:{suffix}"


NANOGPT_PAYGO_REJECTION_CODES = frozenset({"insufficient_balance"})


def is_nanogpt_paygo_rejection(status_code: Any, body: Any) -> bool:
    """True when NanoGPT refused a request for lack of pay-as-you-go balance.

    Provider selection leaves subscription coverage, so an account without a
    funded balance answers 402 no matter which endpoint or model was used.
    """
    if status_code != 402:
        return False
    if isinstance(body, (bytes, bytearray)):
        try:
            body = json.loads(body)
        except (ValueError, TypeError):
            return True
    elif isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return True
    if not isinstance(body, Mapping):
        return True
    code = body.get("code")
    if isinstance(code, str) and code.strip().lower() in NANOGPT_PAYGO_REJECTION_CODES:
        return True
    error = body.get("error")
    if isinstance(error, Mapping):
        nested = error.get("code")
        if isinstance(nested, str):
            return nested.strip().lower() in NANOGPT_PAYGO_REJECTION_CODES
    # A 402 from NanoGPT is a billing refusal even when the shape is unfamiliar.
    return True


def strip_nanogpt_speed_suffix(model: Any) -> Any:
    if not isinstance(model, str) or not nanogpt_model_has_speed_suffix(model):
        return model
    return model.rsplit(":", 1)[0]


def apply_nanogpt_speed_routing(
    payload: Mapping[str, Any],
    suffix: str,
    headers: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Append NanoGPT's provider-selection suffix to the payload model id."""
    upstream_payload = dict(payload)
    if not suffix or nanogpt_speed_routing_conflicts(upstream_payload, headers):
        return upstream_payload
    routed_model = apply_nanogpt_speed_suffix(upstream_payload.get("model"), suffix)
    if routed_model != upstream_payload.get("model"):
        upstream_payload["model"] = routed_model
    return upstream_payload


def sanitize_nanogpt_subscription_payload(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Remove fields that opt a NanoGPT request into PAYG provider routing."""
    return {
        key: value
        for key, value in payload.items()
        if key.lower() not in NANOGPT_SUBSCRIPTION_PAYLOAD_FIELDS
    }


def sanitize_nanogpt_subscription_headers(
    headers: Mapping[str, Any],
) -> dict[str, Any]:
    """Remove caller billing/provider overrides from subscription-only traffic."""
    return {
        key: value
        for key, value in headers.items()
        if str(key).lower() not in NANOGPT_SUBSCRIPTION_PAYGO_HEADERS
    }


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
