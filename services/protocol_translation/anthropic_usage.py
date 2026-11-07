"""Anthropic stop reasons and cache-aware token accounting."""

from collections.abc import Mapping
from typing import Any

from services.protocol_translation.common import chat_usage, non_negative_int, usage_numbers

STOP_TO_FINISH = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "pause_turn": "stop",
    "max_tokens": "length",
    "model_context_window_exceeded": "length",
    "tool_use": "tool_calls",
    "refusal": "content_filter",
}
FINISH_TO_STOP = {
    "stop": "end_turn",
    "length": "max_tokens",
    "tool_calls": "tool_use",
    "function_call": "tool_use",
    "content_filter": "refusal",
}


def anthropic_usage_to_chat(usage: Mapping[str, Any]) -> dict:
    """Chat usage for Claude's top-level usage, which counts the request's model. A
    reply with sampling steps (`usage.iterations`, such as an advisor's) keeps them
    for the ledger and sums the advisor's in `advisor`."""
    converted = _top_level_usage_to_chat(usage)
    steps = usage.get("iterations")
    if isinstance(steps, list) and steps:
        converted["iterations"] = steps
        advisor = advisor_usage(steps)
        if advisor is not None:
            converted["advisor"] = advisor
    return converted


def advisor_usage(steps: list) -> dict | None:
    """OpenAI-shape totals of the advisor's steps, or None when it did not run."""
    from services.usage_types import iterations_from

    advised = [step for step in iterations_from({"iterations": steps}) if step.kind == "advisor_message"]
    if not advised:
        return None
    cached = sum(step.cache_read_input_tokens or 0 for step in advised)
    written = sum(step.cache_creation_input_tokens or 0 for step in advised)
    prompt = sum(step.input_tokens or 0 for step in advised) + cached + written
    completion = sum(step.output_tokens or 0 for step in advised)
    model = next((step.model for step in advised if step.model), None)
    return {
        "model": model if model is None or ":" in model else f"anthropic:{model}",
        "calls": len(advised),
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
        "prompt_tokens_details": {"cached_tokens": cached, "cache_write_tokens": written},
    }


def _top_level_usage_to_chat(usage: Mapping[str, Any]) -> dict:
    from services import prompt_cache_cost

    if prompt_cache_cost.enabled():
        return prompt_cache_cost.anthropic_to_chat(dict(usage))

    def count(key: str) -> int:
        value = usage.get(key)
        return (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value > 0
            else 0
        )

    cached = count("cache_read_input_tokens")
    cache_write = count("cache_creation_input_tokens")
    creation = usage.get("cache_creation")
    one_hour = creation.get("ephemeral_1h_input_tokens") if isinstance(creation, Mapping) else 0
    one_hour = min(non_negative_int(one_hour), cache_write)
    # Anthropic's input_tokens excludes cache reads and writes.
    prompt = count("input_tokens") + cached + cache_write
    return chat_usage(
        prompt,
        count("output_tokens"),
        cached=cached,
        cache_write=cache_write,
        cache_write_1h=one_hour,
    )


def chat_usage_to_anthropic(usage: Any) -> dict:
    from services import prompt_cache_cost

    if prompt_cache_cost.enabled():
        return prompt_cache_cost.chat_to_anthropic(usage)
    numbers = usage_numbers(usage)
    result = {
        "input_tokens": max(
            0, numbers["prompt"] - numbers["cached"] - numbers["cache_write"]
        ),
        "output_tokens": numbers["completion"],
        "cache_creation_input_tokens": numbers["cache_write"],
        "cache_read_input_tokens": numbers["cached"],
    }
    one_hour = min(numbers["cache_write_1h"], numbers["cache_write"])
    if one_hour:
        result["cache_creation"] = cache_creation(numbers["cache_write"], one_hour)
    return result


def cache_creation(cache_write: int, one_hour: int) -> dict:
    """Anthropic's split of cache writes into the 5-minute and one-hour caches."""
    return {
        "ephemeral_5m_input_tokens": cache_write - one_hour,
        "ephemeral_1h_input_tokens": one_hour,
    }
