"""OpenAI-compatible stream payload helpers."""

from __future__ import annotations

from typing import Any, Dict

from streaming.sse import strip_hidden_reasoning_fields


def sanitize_openai_stream_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Drop hidden reasoning metadata while preserving visible content/tool deltas."""

    sanitized = strip_hidden_reasoning_fields(payload)
    return sanitized if isinstance(sanitized, dict) else payload
