"""Bounded provider declarations and optional precision tie breaking."""

from collections.abc import Callable, Mapping, Sequence
from itertools import groupby
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)
_invalid_setting_logged = False

PRECISIONS = frozenset({"fp32", "fp16", "bf16", "fp8", "int8", "int4", "unknown"})
PRECISION_FIELDS = frozenset({"precision", "quantization_scheme", "precision_source"})


def validate_preference(value: Any) -> list[str]:
    """Preferences are a finite, ordered enum list, never model identifiers."""
    if (
        not isinstance(value, list)
        or len(value) > len(PRECISIONS)
        or any(not isinstance(item, str) or item not in PRECISIONS for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError("Invalid precision preference")
    return list(value)


def environment_preference() -> list[str]:
    value = os.environ.get("MODEL_PRECISION_PREFERENCE", "")
    if len(value) > 256:
        raise ValueError("Invalid precision preference")
    if not value.strip():
        return []
    try:
        decoded = json.loads(value)
    except ValueError as error:
        raise ValueError("Invalid precision preference") from error
    return validate_preference(decoded)


def configured_preference() -> list[str]:
    """The environment preference, treating a malformed value as unset.

    Precision only breaks ties, so a typo must not break catalog listings or
    routing; it is logged once and the default behaviour is kept.
    """
    global _invalid_setting_logged
    try:
        return environment_preference()
    except ValueError:
        if not _invalid_setting_logged:
            _invalid_setting_logged = True
            logger.warning("Ignoring invalid MODEL_PRECISION_PREFERENCE; precision preference is off")
        return []


def precision_metadata(metadata: Mapping[str, Any] | None) -> dict[str, str]:
    """Keep explicit declarations only; no name, scheme or capability inference."""
    result: dict[str, str] = {}
    for field in PRECISION_FIELDS:
        value = (metadata or {}).get(field)
        if not isinstance(value, str):
            continue
        if field == "precision":
            if value in PRECISIONS:
                result[field] = value
        elif (
            0 < len(value) <= (128 if field == "quantization_scheme" else 512)
            and value.strip()
            and all(character.isprintable() for character in value)
        ):
            result[field] = value
    return result


def declared_precision(metadata: Mapping[str, Any] | None) -> str:
    return precision_metadata(metadata).get("precision", "unknown")


def catalog_precision_metadata(
    metadata: Mapping[str, Any] | None, provider: str
) -> dict[str, Any]:
    normalized = dict(metadata or {})
    # Disabled catalogs preserve their original shape even for a previously
    # cached opt-in declaration. Existing provenance is retained unchanged.
    for field in PRECISION_FIELDS:
        normalized.pop(field, None)
    if not configured_preference():
        return normalized
    declarations = precision_metadata(metadata)
    if not declarations:
        return normalized
    source = declarations.get("precision_source", f"provider_catalog:{provider}")
    declarations.setdefault("precision", "unknown")
    declarations["precision_source"] = source
    normalized.update(declarations)
    normalized["metadata_provenance"] = {
        **(normalized.get("metadata_provenance") or {}),
        **{field: source for field in declarations if field != "precision_source"},
    }
    return normalized


def prefer_precision(
    ranked: Sequence[tuple[int, dict[str, Any]]],
    preference: list[str],
    tier: Callable[[tuple[int, dict[str, Any]]], tuple],
    metadata: Mapping[str, Mapping[str, Any] | None],
) -> list[dict[str, Any]]:
    """Stable tie breaking inside contiguous approved rank/quality tiers."""
    order = {precision: index for index, precision in enumerate(preference)}
    result = []
    for _, group in groupby(ranked, key=tier):
        result.extend(
            item[1]
            for item in sorted(
                group,
                key=lambda item: order.get(
                    declared_precision(metadata.get(item[1]["model"])), len(order)
                ),
            )
        )
    return result
