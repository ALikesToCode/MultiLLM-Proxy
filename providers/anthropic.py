"""Direct Claude API authentication and model metadata."""

from collections.abc import Mapping
from typing import Any

HAIKU_5_5_MODEL_ID = "claude-haiku-5-5"
ANTHROPIC_MODEL_IDS = (HAIKU_5_5_MODEL_ID,)
ANTHROPIC_REQUEST_HEADER_WHITELIST = {
    "anthropic-beta": "Anthropic-Beta",
    "x-client-request-id": "X-Client-Request-ID",
}


def with_anthropic_headers(
    headers: Mapping[str, str], auth_token: str | None
) -> dict[str, str]:
    """Use the server's Claude key without forwarding proxy bearer credentials."""
    prepared = {
        name: value
        for name, value in headers.items()
        if name.lower() not in {"authorization", "x-api-key"}
    }
    if auth_token:
        prepared["X-Api-Key"] = auth_token
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
