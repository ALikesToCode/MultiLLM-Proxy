"""Generation parameter policy for translated Anthropic requests."""

from collections.abc import Mapping
from typing import Any

from providers.anthropic import ADAPTIVE_THINKING_MODEL_IDS

MIN_THINKING_BUDGET = 1024
THINKING_BUDGETS = {
    "minimal": 1024,
    "low": 2048,
    "medium": 8192,
    "high": 16384,
    "xhigh": 24576,
    "max": 32768,
}
EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh", "max"})


def apply_thinking(body: dict, payload: Mapping[str, Any]) -> None:
    model = body.get("model")
    if isinstance(model, str) and model in ADAPTIVE_THINKING_MODEL_IDS:
        _apply_adaptive_thinking(body, payload)
        return
    thinking = payload.get("thinking")
    if isinstance(thinking, Mapping) and thinking.get("type") in {
        "enabled",
        "disabled",
        "adaptive",
    }:
        body["thinking"] = dict(thinking)
    else:
        effort = payload.get("reasoning_effort")
        if effort is None and isinstance(payload.get("reasoning"), Mapping):
            effort = payload["reasoning"].get("effort")
        if effort not in EFFORTS:
            return
        if effort == "none":
            body["thinking"] = {"type": "disabled"}
            return
        body["thinking"] = {
            "type": "enabled",
            "budget_tokens": THINKING_BUDGETS[effort],
        }
    if body["thinking"].get("type") == "disabled":
        return
    budget = body["thinking"].get("budget_tokens")
    max_tokens = body["max_tokens"]
    if (
        isinstance(budget, int)
        and not isinstance(budget, bool)
        and isinstance(max_tokens, int)
        and budget >= max_tokens
    ):
        # budget_tokens must stay below max_tokens; shrink it or drop thinking.
        if max_tokens - 1 < MIN_THINKING_BUDGET:
            body.pop("thinking")
            return
        body["thinking"]["budget_tokens"] = max_tokens - 1
    # Thinking accepts neither a modified temperature nor top_p below 0.95.
    body.pop("temperature", None)
    top_p = body.get("top_p")
    if isinstance(top_p, (int, float)) and top_p < 0.95:
        body.pop("top_p")


def _apply_adaptive_thinking(body: dict, payload: Mapping[str, Any]) -> None:
    # Claude 5.5 models reject manual budgets and most client sampling defaults.
    for field in ("temperature", "top_p", "top_k"):
        body.pop(field, None)
    output_config = payload.get("output_config")
    if isinstance(output_config, Mapping):
        body["output_config"] = {**output_config, **body.get("output_config", {})}
    thinking = payload.get("thinking")
    if isinstance(thinking, Mapping) and thinking.get("type") in {
        "enabled",
        "disabled",
        "adaptive",
    }:
        body["thinking"] = dict(thinking)
        body["thinking"].pop("budget_tokens", None)
        if thinking["type"] == "enabled":
            body["thinking"]["type"] = "adaptive"
    effort = payload.get("reasoning_effort")
    if effort is None and isinstance(payload.get("reasoning"), Mapping):
        effort = payload["reasoning"].get("effort")
    if effort not in EFFORTS:
        return
    if effort == "none":
        body["thinking"] = {"type": "disabled"}
        effort = "low"
    elif "thinking" not in body:
        body["thinking"] = {"type": "adaptive"}
    body.setdefault("output_config", {})["effort"] = (
        "low" if effort == "minimal" else effort
    )


def reasoning_effort(payload: Mapping[str, Any]) -> str | None:
    config = payload.get("output_config")
    effort = config.get("effort") if isinstance(config, Mapping) else None
    if effort in EFFORTS and effort != "none":
        # Chat Completions has no "max"; the gateway maps xhigh to each provider's top tier.
        return "xhigh" if effort == "max" else str(effort)
    thinking = payload.get("thinking")
    if isinstance(thinking, Mapping) and thinking.get("type") == "enabled":
        budget = thinking.get("budget_tokens")
        if isinstance(budget, int) and not isinstance(budget, bool):
            if budget < 4096:
                return "low"
            return "medium" if budget < 16384 else "high"
    return None


def output_format(payload: Mapping[str, Any]) -> dict | None:
    config = payload.get("output_config")
    candidates = [
        config.get("format") if isinstance(config, Mapping) else None,
        payload.get("output_format"),
    ]
    for fmt in candidates:
        if (
            isinstance(fmt, Mapping)
            and fmt.get("type") == "json_schema"
            and isinstance(fmt.get("schema"), Mapping)
        ):
            return {
                "type": "json_schema",
                "json_schema": {"name": "output", "schema": dict(fmt["schema"]), "strict": True},
            }
    return None
