import json
from collections.abc import Mapping
from typing import Any

CATALOG_METADATA_FIELDS = frozenset(
    {
        "object",
        "created",
        "owned_by",
        "endpoint",
        "token_multiplier",
        "premium",
        "required_plan",
        "context_window",
        "max_output_tokens",
        "input_modalities",
        "output_modalities",
        "modality",
        "tokenizer",
        "supports_vision",
        "supports_tools",
        "supports_function_calling",
        "supports_reasoning",
        "supports_json_mode",
        "supports_audio_input",
        "supports_image_output",
        "supports_streaming",
        "description",
        "pricing",
        "metadata_source",
        "metadata_resolved_from",
        "metadata_status",
    }
)
_METADATA_MAX_BYTES = 65_536
_STRING_MAX_LENGTH = 16_384
_STRING_FIELDS = frozenset(
    {
        "object",
        "owned_by",
        "endpoint",
        "required_plan",
        "modality",
        "tokenizer",
        "description",
        "metadata_source",
        "metadata_resolved_from",
        "metadata_status",
    }
)
_INTEGER_FIELDS = frozenset(
    {"created", "context_window", "max_output_tokens"}
)
_BOOLEAN_FIELDS = frozenset(
    {
        "premium",
        "supports_vision",
        "supports_tools",
        "supports_function_calling",
        "supports_reasoning",
        "supports_json_mode",
        "supports_audio_input",
        "supports_image_output",
        "supports_streaming",
    }
)
_MODALITY_FIELDS = frozenset({"input_modalities", "output_modalities"})
_INVALID = object()


def _sanitize_value(key: str, value: Any) -> Any:
    if value is None:
        return None
    if key in _STRING_FIELDS:
        if isinstance(value, str) and len(value) <= _STRING_MAX_LENGTH:
            return value
        return _INVALID
    if key in _INTEGER_FIELDS:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return _INVALID
    if key == "token_multiplier":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value
        return _INVALID
    if key in _BOOLEAN_FIELDS:
        return value if isinstance(value, bool) else _INVALID
    if key in _MODALITY_FIELDS:
        if (
            isinstance(value, list)
            and len(value) <= 32
            and all(
                isinstance(item, str) and len(item) <= 256
                for item in value
            )
        ):
            return value
        return _INVALID
    if key == "pricing":
        if not isinstance(value, Mapping) or len(value) > 32:
            return _INVALID
        pricing: dict[str, Any] = {}
        for price_key, price_value in value.items():
            if not isinstance(price_key, str) or len(price_key) > 128:
                return _INVALID
            if price_value is not None and not (
                isinstance(price_value, str)
                or (
                    isinstance(price_value, (int, float))
                    and not isinstance(price_value, bool)
                )
            ):
                return _INVALID
            pricing[price_key] = price_value
        return pricing
    return _INVALID


def sanitize_provider_metadata(item: Any) -> dict[str, Any] | None:
    """Keep bounded, documented model-catalog fields from untrusted providers."""
    if not isinstance(item, Mapping):
        return None

    metadata: dict[str, Any] = {}
    for key in CATALOG_METADATA_FIELDS:
        if key not in item:
            continue
        value = _sanitize_value(key, item[key])
        if value is _INVALID:
            continue
        try:
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            decoded = json.loads(encoded)
        except (TypeError, ValueError, OverflowError):
            continue
        if len(encoded.encode("utf-8")) <= _METADATA_MAX_BYTES:
            metadata[key] = decoded

    if not metadata:
        return None
    encoded_metadata = json.dumps(
        metadata,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (
        metadata
        if len(encoded_metadata.encode("utf-8")) <= _METADATA_MAX_BYTES
        else None
    )


def encode_provider_metadata(metadata: Any) -> str | None:
    sanitized = sanitize_provider_metadata(metadata)
    if sanitized is None:
        return None
    return json.dumps(
        sanitized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def decode_provider_metadata(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return None
    return sanitize_provider_metadata(decoded)
