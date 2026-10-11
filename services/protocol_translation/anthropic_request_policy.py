"""Generation parameter policy for translated Anthropic requests."""

from collections.abc import Mapping
from typing import Any

from providers.anthropic import HAIKU_5_5_MODEL_ID

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
    if body.get("model") == HAIKU_5_5_MODEL_ID:
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
    # Haiku 5.5 rejects manual budgets and most client sampling defaults.
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
