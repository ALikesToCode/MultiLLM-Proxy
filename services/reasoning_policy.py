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
NANOGPT_GLM_REASONING_CEILINGS = {
    "glm-5.1": "high",
    "glm-5.2": "max",
    "glm-5.3": "max",
    "glm-5.3-flash": "max",
}


def is_glm_52_model(model: str) -> bool:
    model_name = model.strip().lower().rsplit("/", 1)[-1]
    return model_name.split(":", 1)[0] == "glm-5.2"


def is_glm_5_model(model: str) -> bool:
    if not isinstance(model, str):
        return False
    model_name = model.strip().lower().rsplit("/", 1)[-1]
    return model_name.split(":", 1)[0].startswith("glm-5.")


def _maximum_effort(provider: str, model: str) -> str:
    model_name = model.strip().lower().rsplit("/", 1)[-1].split(":", 1)[0]
    if provider == "nanogpt" and "glm-5.3-flash-uncensored" in model_name:
        return "high"
    if provider == "nanogpt" and model_name in NANOGPT_GLM_REASONING_CEILINGS:
        # NanoGPT's model catalog lists native GLM tiers separately from the
        # generic Chat Completions effort enum. Preserve its literal `max`.
        return NANOGPT_GLM_REASONING_CEILINGS[model_name]
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
    """Apply GLM-5.x defaults and map explicit effort onto the provider contract."""
    normalized = dict(payload)
    if not is_glm_5_model(model):
        return normalized

    provider_name = provider.lower()
    maximum = _maximum_effort(provider_name, model)
    specified, requested = _requested_effort(normalized)
    if provider_name == "nanogpt" and not specified:
        # Preserve NanoGPT's native thinking mode unless the caller selects
        # an effort; the generic maximum overlay changes provider behavior.
        return normalized
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
    # OpenCode Go enables GLM reasoning through reasoning_effort. Its upstream
    # rejects the Z.AI-specific top-level thinking field; never inject it.
    return normalized


def apply_glm_52_reasoning_policy(
    payload: Mapping[str, Any],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Compatibility alias for callers using the original GLM-5.2 name."""
    return apply_glm_5_reasoning_policy(payload, provider, model)
