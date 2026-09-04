from __future__ import annotations

from collections.abc import Mapping
from typing import Any

REASONING_EFFORT_ORDER = (
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
)
GLM_52_MAX_REASONING_EFFORTS = {
    "linkapi": "high",
    "nanogpt": "xhigh",
    "navyai": "max",
    "opencode": "max",
    "openrouter": "xhigh",
}


def is_glm_52_model(model: str) -> bool:
    model_name = model.strip().lower().rsplit("/", 1)[-1]
    return model_name.split(":", 1)[0] == "glm-5.2"


def is_glm_5_model(model: str) -> bool:
    model_name = model.strip().lower().rsplit("/", 1)[-1]
    return model_name.split(":", 1)[0].startswith("glm-5.")


def _maximum_effort(provider: str, model: str) -> str:
    model_name = model.strip().lower()
    if provider == "nanogpt" and "glm-5.3-flash-uncensored" in model_name:
        return "high"
    return GLM_52_MAX_REASONING_EFFORTS.get(provider, "max")


def _requested_effort(payload: Mapping[str, Any]) -> tuple[bool, str | None]:
    direct = payload.get("reasoning_effort")
    if "reasoning_effort" in payload:
        if isinstance(direct, str) and direct.lower() in REASONING_EFFORT_ORDER:
            return True, direct.lower()
        return True, None
    nested = payload.get("reasoning")
    if "reasoning" in payload and isinstance(nested, Mapping):
        effort = nested.get("effort")
        if isinstance(effort, str) and effort.lower() in REASONING_EFFORT_ORDER:
            return True, effort.lower()
        return True, None
    if "reasoning" in payload:
        return True, None
    return False, None


def _bounded_effort(requested: str, maximum: str) -> str:
    # Direct GLM transports call their strongest tier `max`; `xhigh` is an
    # alternate gateway spelling and must not be forwarded to those contracts.
    if requested == "xhigh" and maximum == "max":
        return "max"
    requested_index = REASONING_EFFORT_ORDER.index(requested)
    maximum_index = REASONING_EFFORT_ORDER.index(maximum)
    return REASONING_EFFORT_ORDER[min(requested_index, maximum_index)]


def apply_glm_5_reasoning_policy(
    payload: Mapping[str, Any],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Default GLM-5.x to its maximum and map onto the provider contract."""
    normalized = dict(payload)
    if not is_glm_5_model(model):
        return normalized

    provider_name = provider.lower()
    maximum = _maximum_effort(provider_name, model)
    specified, requested = _requested_effort(normalized)
    if specified and requested is None:
        return normalized
    effort = _bounded_effort(requested or "max", maximum)
    nested = normalized.get("reasoning")
    normalized.pop("reasoning", None)
    normalized.pop("reasoning_effort", None)
    if provider_name == "openrouter":
        normalized["reasoning"] = {
            **(dict(nested) if isinstance(nested, Mapping) else {}),
            "effort": effort,
        }
    else:
        normalized["reasoning_effort"] = effort
    return normalized


def apply_glm_52_reasoning_policy(
    payload: Mapping[str, Any],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Compatibility alias for callers using the original GLM-5.2 name."""
    return apply_glm_5_reasoning_policy(payload, provider, model)
