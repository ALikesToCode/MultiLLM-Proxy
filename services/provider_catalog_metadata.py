import json
import math
import re
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
        "vision_metadata_source",
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
        "input_cost_per_million",
        "output_cost_per_million",
        "metadata_provenance",
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
        "vision_metadata_source",
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
# Normalized USD list prices per million tokens; upstream `pricing` keeps its own shape.
_PRICE_FIELDS = frozenset({"input_cost_per_million", "output_cost_per_million"})
_PROVENANCE_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}")
_INVALID = object()


def _modalities(value: Any) -> list[str] | None:
    if isinstance(value, str) and len(value) <= 1024:
        value = value.split(",")
    if not isinstance(value, list) or not 0 < len(value) <= 32:
        return None
    if not all(isinstance(item, str) and 0 < len(item.strip()) <= 256 for item in value):
        return None
    return list(dict.fromkeys(item.strip().lower() for item in value))


def _normalized_modalities(item: Mapping[str, Any]) -> dict[str, list[str]]:
    normalized = {}
    architecture = item.get("architecture")
    nested = item.get("modalities")
    for direction in ("input", "output"):
        field = f"{direction}_modalities"
        candidates = [item.get(field)]
        if isinstance(architecture, Mapping):
            candidates.append(architecture.get(field))
        if isinstance(nested, Mapping):
            candidates.append(nested.get(direction))
        for candidate in candidates:
            modalities = _modalities(candidate)
            if modalities:
                normalized[field] = modalities
                break
    return normalized


def model_supports_vision(metadata: Mapping[str, Any] | None) -> bool | None:
    """Resolve model input support; transport defaults and output images are not evidence."""
    metadata = metadata or {}
    explicit = metadata.get("supports_vision")
    if isinstance(explicit, bool):
        return explicit
    modalities = _normalized_modalities(metadata).get("input_modalities")
    if modalities:
        return "image" in modalities or "images" in modalities
    return None


def model_supports_tools(metadata: Mapping[str, Any] | None) -> bool | None:
    """Resolve model tool calling from explicit catalog flags; unknown stays None."""
    metadata = metadata or {}
    for field in ("supports_tools", "supports_function_calling"):
        if isinstance(metadata.get(field), bool):
            return metadata[field]
    return None


def _declared_tool_support(item: Mapping[str, Any]) -> dict[str, bool]:
    """OpenRouter-style catalogs list accepted request parameters per model."""
    if model_supports_tools(item) is not None:
        return {}
    parameters = item.get("supported_parameters")
    if (
        not isinstance(parameters, list)
        or len(parameters) > 128
        or not all(isinstance(value, str) and len(value) <= 128 for value in parameters)
    ):
        return {}
    return {"supports_tools": "tools" in parameters}


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
    if key in _PRICE_FIELDS:
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value >= 0
        ):
            return value
        return _INVALID
    if key == "metadata_provenance":
        if not isinstance(value, Mapping) or len(value) > 32:
            return _INVALID
        if not all(
            isinstance(field, str)
            and _PROVENANCE_KEY.fullmatch(field)
            and isinstance(source, str)
            and 0 < len(source) <= 512
            for field, source in value.items()
        ):
            return _INVALID
        return dict(value)
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

    item = {**item, **_normalized_modalities(item), **_declared_tool_support(item)}
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
