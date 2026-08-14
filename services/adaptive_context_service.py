from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

from services.context_optimizer import (
    ContextOptimizationError,
    ContextOptimizationResult,
    estimate_payload_tokens,
    optimize_chat_payload,
)
from services.reasoning_policy import is_glm_52_model

logger = logging.getLogger(__name__)

DEFAULT_GLM_TRIGGER_TOKENS = 8_000
DEFAULT_GLM_KEEP_RECENT_TURNS = 8


def _enabled() -> bool:
    value = os.environ.get("GLM_AUTO_OPTIMIZE", "true")
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name)
    try:
        value = int(raw_value) if raw_value is not None else default
    except (TypeError, ValueError):
        logger.warning("Invalid integer for %s; using default %s", name, default)
        return default
    return min(max(value, minimum), maximum)


def apply_adaptive_glm_context(
    payload: Mapping[str, Any],
    *,
    model: str,
    default_target_tokens: int,
) -> ContextOptimizationResult | None:
    """Safely compact eligible old prompt text before a GLM-5.2 request."""
    if not is_glm_52_model(model) or not _enabled():
        return None
    if "optimization" in payload:
        # Explicit optimization belongs to /optimize/v1/chat/completions. Keep
        # the normal route's existing pass-through behavior for compatibility.
        return None

    trigger_input_tokens = _bounded_env_int(
        "GLM_AUTO_OPTIMIZE_TRIGGER_TOKENS",
        DEFAULT_GLM_TRIGGER_TOKENS,
        0,
        10_000_000,
    )
    try:
        if estimate_payload_tokens(payload) <= trigger_input_tokens:
            return None
    except (TypeError, ValueError):
        return None

    adaptive_payload = dict(payload)
    adaptive_payload["optimization"] = {
        "mode": "deterministic",
        "target_input_tokens": max(64, default_target_tokens),
        "trigger_input_tokens": trigger_input_tokens,
        "keep_recent_turns": _bounded_env_int(
            "GLM_AUTO_OPTIMIZE_KEEP_RECENT_TURNS",
            DEFAULT_GLM_KEEP_RECENT_TURNS,
            1,
            64,
        ),
        "image_prompt_history": "latest",
        "media_history": "all",
        "require_target": False,
    }
    try:
        return optimize_chat_payload(
            adaptive_payload,
            default_target_tokens=default_target_tokens,
        )
    except ContextOptimizationError as error:
        logger.info(
            "Adaptive GLM context optimization skipped (%s)",
            type(error).__name__,
        )
        return None
