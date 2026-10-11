"""Anthropic stop reasons and cache-aware token accounting."""

from collections.abc import Mapping
from typing import Any

from services.protocol_translation.common import chat_usage, usage_numbers

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
    # Anthropic's input_tokens excludes cache reads and writes.
    prompt = count("input_tokens") + cached + cache_write
    return chat_usage(
        prompt, count("output_tokens"), cached=cached, cache_write=cache_write
    )


def chat_usage_to_anthropic(usage: Any) -> dict:
    from services import prompt_cache_cost

    if prompt_cache_cost.enabled():
        return prompt_cache_cost.chat_to_anthropic(usage)
    numbers = usage_numbers(usage)
    return {
        "input_tokens": max(
            0, numbers["prompt"] - numbers["cached"] - numbers["cache_write"]
        ),
        "output_tokens": numbers["completion"],
        "cache_creation_input_tokens": numbers["cache_write"],
        "cache_read_input_tokens": numbers["cached"],
    }
