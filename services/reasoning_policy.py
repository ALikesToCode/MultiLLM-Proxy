from __future__ import annotations

import re
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


MIMO_EFFORT_MODELS = frozenset({"mimo-v2.6-pro"})


def is_mimo_effort_model(model: str) -> bool:
    if not isinstance(model, str):
        return False
    model_name = model.strip().lower().rsplit("/", 1)[-1]
    return model_name.split(":", 1)[0] in MIMO_EFFORT_MODELS


def apply_mimo_reasoning_policy(payload: Mapping[str, Any], model: str) -> dict[str, Any]:
    """Map an explicit effort onto MiMo v2.6 Pro's two values.

    NanoGPT's MiMo v2.6 Pro accepts only `none` or `high` and refuses anything else
    with a 400 (observed 2026-10-02), so callers' generic efforts would otherwise fail
    the whole attempt. `none` and `minimal` stay off; every other effort thinks at `high`.
    An omitted effort keeps the model's own default.
    """
    normalized = dict(payload)
    if not is_mimo_effort_model(model):
        return normalized
    specified, requested = _requested_effort(normalized)
    if not specified or requested is None:
        return normalized
    effort = "none" if requested in ("none", "minimal") else "high"
    if "reasoning_effort" in normalized:
        normalized["reasoning_effort"] = effort
    else:
        nested = normalized.get("reasoning")
        normalized["reasoning"] = {**(dict(nested) if isinstance(nested, Mapping) else {}), "effort": effort}
    return normalized


GEMINI_EFFORTS = {
    "none": "minimal",
    "minimal": "minimal",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",
    "max": "high",
}


_GEMINI_VERSIONED = re.compile(r"^gemini-(\d+)\.(\d+)-(flash|pro)(-lite)?\b")


def gemini_rejects_minimal(model: str) -> bool:
    """Gemini 3.7 Flash and later Flash models, and every Pro, refuse `minimal` with a 400.

    Google's thinking-level table (ai.google.dev/gemini-api/docs/thinking) lists `minimal` as
    unsupported for 3.8 and 3.7 Flash and for 3.1 Pro; 3.6 and 3.5 Flash and the Flash-Lite
    models accept it. Later Flash versions are assumed to keep the 3.7 behavior.
    """
    if not isinstance(model, str):
        return False
    match = _GEMINI_VERSIONED.match(model.strip().lower().rsplit("/", 1)[-1])
    if match is None or match.group(4):
        return False
    major, minor, family = int(match.group(1)), int(match.group(2)), match.group(3)
    return family == "pro" or (major, minor) >= (3, 7)


def apply_gemini_reasoning_policy(
    payload: Mapping[str, Any], provider: str, model: str = ""
) -> dict[str, Any]:
    """Fit an explicit effort to the levels Gemini's Chat Completions endpoint accepts.

    Gemini thinks at minimal, low, medium or high; it has no `none`, `xhigh` or `max`,
    so those become the nearest level it has. Models without `minimal` think at `low`
    instead. An omitted effort keeps the model's default.
    """
    normalized = dict(payload)
    if provider != "gemini":
        return normalized
    specified, requested = _requested_effort(normalized)
    if not specified or requested is None:
        return normalized
    effort = GEMINI_EFFORTS[requested]
    if effort == "minimal" and gemini_rejects_minimal(model):
        effort = "low"
    normalized.pop("reasoning", None)
    normalized["reasoning_effort"] = effort
    return normalized


# Codex Everywhere's Pro pool refuses `minimal` for GPT-6.1 Sol (three refusals on
# 2026-10-05) while the Plus pool accepts it. Sol thinks at `low` on both pools, so a
# fallback from one pool to the other sends the same effort.
SOL_POOLS = frozenset({"ce-gpt-plus", "ce-gpt-pro"})


def apply_sol_reasoning_policy(
    payload: Mapping[str, Any], provider: str, model: str = ""
) -> dict[str, Any]:
    """Raise GPT-6.1 Sol's `minimal` effort to `low`; every other effort is unchanged."""
    normalized = dict(payload)
    name = model.strip().lower().rsplit("/", 1)[-1] if isinstance(model, str) else ""
    if provider not in SOL_POOLS or not name.startswith("gpt-6.1-sol"):
        return normalized
    specified, requested = _requested_effort(normalized)
    if not specified or requested != "minimal":
        return normalized
    if "reasoning_effort" in normalized:
        normalized["reasoning_effort"] = "low"
    else:
        normalized["reasoning"] = {**dict(normalized["reasoning"]), "effort": "low"}
    return normalized


def apply_glm_52_reasoning_policy(
    payload: Mapping[str, Any],
    provider: str,
    model: str,
) -> dict[str, Any]:
    """Compatibility alias for callers using the original GLM-5.2 name."""
    return apply_glm_5_reasoning_policy(payload, provider, model)
