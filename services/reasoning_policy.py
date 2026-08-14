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
    "navyai": "xhigh",
    "opencode": "max",
    "openrouter": "xhigh",
}


def _is_glm_52(model: str) -> bool:
    return model.strip().lower().rsplit("/", 1)[-1] == "glm-5.2"


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
    requested_index = REASONING_EFFORT_ORDER.index(requested)
    maximum_index = REASONING_EFFORT_ORDER.index(maximum)
    return REASONING_EFFORT_ORDER[min(requested_index, maximum_index)]


def apply_glm_52_reasoning_policy(
    payload: Mapping[str, Any],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Default GLM-5.2 to max and map effort onto the provider contract."""
    normalized = dict(payload)
    if not _is_glm_52(model):
        return normalized

    provider_name = provider.lower()
    maximum = GLM_52_MAX_REASONING_EFFORTS.get(provider_name, "max")
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
