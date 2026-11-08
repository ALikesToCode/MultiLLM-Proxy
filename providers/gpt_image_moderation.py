from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from providers.model_versions import gpt_image_version

GPT_IMAGE_MODERATION_VALUES = frozenset({"auto", "low"})


def is_gpt_image_model(model_id: Any) -> bool:
    """Recognize every GPT Image version and relay-specific suffixed aliases.

    The version is parsed rather than listed, so a new release such as gpt-image-2.6
    gets the low moderation default without a code change.
    """
    return gpt_image_version(model_id) is not None


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
