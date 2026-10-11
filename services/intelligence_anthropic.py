"""Anthropic protocol translation within the intelligence attempt boundary."""

import json

from providers.anthropic import HAIKU_5_5_MODEL_ID
from services.intelligence_contract import GatewayError
from services.protocol_translation import (
    CHAT,
    MESSAGES,
    TranslationError,
    UpstreamFailure,
    translate_request,
    translate_response,
)
from services.protocol_translation.anthropic import messages_sse_items
from services.protocol_translation.common import chat_items_to_sse, guarded_items
from streaming.sse import iter_sse_events

HAIKU_INTELLIGENCE_MODEL = f"anthropic:{HAIKU_5_5_MODEL_ID}"


def prepare_anthropic_request(body):
    if body["model"] == HAIKU_5_5_MODEL_ID:
        body = {"reasoning_effort": "max", **body}
    try:
        return translate_request(body, CHAT, MESSAGES)
    except TranslationError:
        raise GatewayError(
            "invalid_routing_request",
            "The request cannot be translated to Anthropic Messages.",
            400,
        ) from None


def complete_usage(usage):
    """Missing or malformed native counts must retain the gateway reservation."""
    return (
        isinstance(usage, dict)
        and all(
            type(usage.get(key)) is int and usage[key] >= 0
            for key in ("input_tokens", "output_tokens")
        )
        and all(
            key not in usage or type(usage[key]) is int and usage[key] >= 0
            for key in ("cache_read_input_tokens", "cache_creation_input_tokens")
        )
    )


class AnthropicExchange:
    """Convert one bounded exchange without dispatching or retrying another request."""

    def __init__(self, exchange, model, max_bytes):
        self.exchange, self.model, self.max_bytes = exchange, model, max_bytes
        self.native_usage = {}
        self.output_usage_received = False

    def head(self):
        return self.exchange.head()

    def close(self):
        self.exchange.close()

    def read(self):
        try:
            native = json.loads(self.exchange.read())
            if (
                not isinstance(native, dict)
                or "error" in native
                or native.get("type") != "message"
                or native.get("role") != "assistant"
                or not isinstance(native.get("content"), list)
                or not isinstance(native.get("stop_reason"), str)
                or not native["stop_reason"]
            ):
                raise UpstreamFailure("Invalid Anthropic message")
            translated = translate_response(native, MESSAGES, CHAT, model=self.model)
            if not complete_usage(native.get("usage")):
                translated.pop("usage", None)
            encoded = json.dumps(translated, separators=(",", ":")).encode()
        except (ValueError, UnicodeError, UpstreamFailure):
            raise GatewayError(
                "invalid_upstream_response",
                "The provider returned an invalid Anthropic response.",
                502,
            ) from None
        self._check_size(len(encoded))
        return encoded

    def chunks(self):
        size = 0
        for chunk in chat_items_to_sse(guarded_items(self._items()), model=self.model):
            encoded = chunk.encode()
            size += len(encoded)
            self._check_size(size)
            yield encoded

    def _items(self):
        for item in messages_sse_items(self._native_chunks()):
            if (
                isinstance(item, dict)
                and "usage" in item
                and not (
                    self.output_usage_received and complete_usage(self.native_usage)
                )
            ):
                item = {key: value for key, value in item.items() if key != "usage"}
            yield item

    def _native_chunks(self):
        # Observe native counts before the shared translator supplies defaults.
        # A stream with no usage must never become a complete zero-token charge.
        for event in iter_sse_events(self.exchange.chunks()):
            if event.data:
                try:
                    body = json.loads(event.data)
                except ValueError:
                    body = None
                if isinstance(body, dict):
                    self._observe_usage(body)
            lines = [f": {comment}" for comment in event.comments]
            if event.event:
                lines.append(f"event: {event.event}")
            if event.data:
                lines.extend(f"data: {line}" for line in event.data.split("\n"))
            yield "\n".join(lines) + "\n\n"

    def _observe_usage(self, body):
        if body.get("type") not in {"message_start", "message_delta"}:
            return
        message = body.get("message")
        usage = (
            message.get("usage")
            if body.get("type") == "message_start" and isinstance(message, dict)
            else body.get("usage")
        )
        if not isinstance(usage, dict):
            return
        self.native_usage.update(usage)
        if body.get("type") == "message_delta" and "output_tokens" in usage:
            # message_start's zero is only a placeholder. A final malformed count
            # must invalidate it rather than silently charging zero output tokens.
            self.output_usage_received = (
                type(usage["output_tokens"]) is int and usage["output_tokens"] >= 0
            )

    def _check_size(self, size):
        if size > self.max_bytes:
            raise GatewayError(
                "response_too_large",
                "The provider response exceeded the gateway limit.",
                502,
            )
