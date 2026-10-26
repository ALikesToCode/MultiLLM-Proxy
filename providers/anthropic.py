"""Direct Claude API authentication and model metadata."""

import json
from collections.abc import Mapping
from typing import Any

HAIKU_5_5_MODEL_ID = "claude-haiku-5-5"
ANTHROPIC_MODEL_IDS = (HAIKU_5_5_MODEL_ID,)
ANTHROPIC_REQUEST_HEADER_WHITELIST = {
    "anthropic-beta": "Anthropic-Beta",
    "x-client-request-id": "X-Client-Request-ID",
}
# An account that ran out of credit or reached a spend limit stays refused until its owner
# acts, so its key rests for the longest cooldown instead of being retried every minute.
ANTHROPIC_REFUSAL_REST_SECONDS = 3600
_REFUSAL_BODY_LIMIT = 65_536
_SPEND_LIMIT_MESSAGES = (
    "You have reached your specified API usage limits",
    "You have reached your specified workspace API usage limits",
)


def _header(headers: Any, name: str) -> str:
    getter = getattr(headers, "get", None)
    if getter is None:
        return ""
    value = getter(name)
    if value is None:
        value = next(
            (item for key, item in headers.items() if str(key).lower() == name.lower()),
            None,
        )
    return value if isinstance(value, str) else ""


def anthropic_credential_refusal(response: Any) -> str | None:
    """Name the account-wide refusal in a Claude API error response, or return None.

    Anthropic reports an empty credit balance and a spend limit set by the account owner
    as 400 invalid_request_error, the same shape as a malformed request, so only the
    message tells them apart. A tier spend cap is a 429 with a distinct error code. Reading
    the small JSON error body caches it on the response, so relays still forward it.
    """
    status = getattr(response, "status_code", None)
    if status == 402:
        return "billing_error"
    if status not in (400, 429):
        return None
    headers = getattr(response, "headers", None) or {}
    if "json" not in _header(headers, "Content-Type").lower():
        return None
    length = _header(headers, "Content-Length")
    if length and (not length.isdigit() or int(length) > _REFUSAL_BODY_LIMIT):
        return None
    try:
        body = response.content
    except Exception:  # A body that cannot be read is not evidence of a refusal.
        return None
    try:
        error = json.loads(body).get("error") if len(body) <= _REFUSAL_BODY_LIMIT else None
    except (AttributeError, TypeError, ValueError, RecursionError):
        return None
    if not isinstance(error, Mapping):
        return None
    if status == 429:
        details = error.get("details")
        code = details.get("error_code") if isinstance(details, Mapping) else None
        return "spend_cap" if code == "enforced_spend_limit_reached" else None
    message = error.get("message")
    if error.get("type") != "invalid_request_error" or not isinstance(message, str):
        return None
    if message.startswith("Your credit balance is too low"):
        return "credit_exhausted"
    if message.startswith(_SPEND_LIMIT_MESSAGES):
        return "spend_limit"
    return None


def with_anthropic_headers(
    headers: Mapping[str, str], auth_token: str | None, *, workspace_id: str | None = None
) -> dict[str, str]:
    """Use the server's Claude key without forwarding proxy bearer credentials."""
    prepared = {
        name: value
        for name, value in headers.items()
        if name.lower() not in {"authorization", "x-api-key", "anthropic-workspace-id"}
    }
    if auth_token:
        prepared["X-Api-Key"] = auth_token
    if workspace_id and workspace_id.strip():
        prepared["Anthropic-Workspace-Id"] = workspace_id.strip()
    if not any(name.lower() == "anthropic-version" for name in prepared):
        prepared["Anthropic-Version"] = "2023-06-01"
    return prepared


def anthropic_model_metadata(
    model_id: str, metadata: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    defaults: dict[str, Any] = {}
    if model_id == HAIKU_5_5_MODEL_ID:
        defaults = {
            "context_window": 1_000_000,
            "max_output_tokens": 128_000,
            "input_modalities": ["text", "image"],
            "output_modalities": ["text"],
            "supports_vision": True,
            "supports_tools": True,
            "supports_reasoning": True,
        }
    return {
        **defaults,
        **(metadata or {}),
        "api_endpoint": "/v1/messages",
        "api_protocol": "anthropic_messages",
    }


def anthropic_catalog_metadata(item: Any) -> Any:
    """Normalize the Models API's nested capability flags for the shared catalog."""
    if not isinstance(item, Mapping):
        return item
    normalized = dict(item)
    capabilities = item.get("capabilities")
    if isinstance(capabilities, Mapping):
        for capability, field in (
            ("image_input", "supports_vision"),
            ("thinking", "supports_reasoning"),
        ):
            details = capabilities.get(capability)
            supported = (
                details.get("supported") if isinstance(details, Mapping) else None
            )
            if isinstance(supported, bool):
                normalized[field] = supported
    return normalized
