from __future__ import annotations

from collections.abc import Mapping
from typing import Any

GPT_IMAGE_MODEL_FAMILIES = (
    "gpt-image-1",
    "gpt-image-1-mini",
    "gpt-image-1.5",
    "gpt-image-2",
)
GPT_IMAGE_MODERATION_VALUES = frozenset({"auto", "low"})


def is_gpt_image_model(model_id: Any) -> bool:
    """Recognize official GPT Image IDs and relay-specific suffixed aliases."""
    normalized = str(model_id or "").strip().lower()
    if not normalized:
        return False
    if ":" in normalized:
        normalized = normalized.split(":", 1)[1]
    basename = normalized.rsplit("/", 1)[-1]
    return any(
        basename == family or basename.startswith(f"{family}-")
        for family in GPT_IMAGE_MODEL_FAMILIES
    )


def apply_gpt_image_moderation_default(
    payload: Mapping[str, Any],
    *,
    model_id: Any = None,
) -> tuple[dict[str, Any], bool]:
    """Default GPT Image generations to low moderation without mutating input."""
    normalized = dict(payload)
    selected_model = model_id if model_id is not None else normalized.get("model")
    if not is_gpt_image_model(selected_model):
        return normalized, False

    moderation = normalized.get("moderation")
    if moderation is None:
        normalized["moderation"] = "low"
        return normalized, True
    if moderation not in GPT_IMAGE_MODERATION_VALUES:
        raise ValueError("GPT Image moderation must be one of: auto, low")
    return normalized, False
