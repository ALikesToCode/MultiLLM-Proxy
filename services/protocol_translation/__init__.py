"""Stateless translation between Chat Completions, Responses and Anthropic Messages.

Chat Completions is the pivot: every other pair is composed through it, request
by request and stream event by stream event. See docs/protocol-translation.md
for what maps, what is dropped and what is rejected.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any

from services.protocol_translation.anthropic import (
    chat_items_to_messages_sse,
    chat_request_to_messages,
    chat_response_to_messages,
    messages_request_to_chat,
    messages_response_to_chat,
    messages_sse_items,
    strip_unsigned_thinking,
)
from services.protocol_translation.common import (
    CHAT,
    MESSAGES,
    OPENAI_FAMILY,
    PROTOCOLS,
    RESPONSES,
    ChatItem,
    StreamComment,
    StreamFailure,
    TranslationError,
    UpstreamFailure,
    aggregate_chat_items,
    anthropic_error_body,
    chat_completion_items,
    chat_items_to_sse,
    chat_sse_items,
    error_details,
    guarded_items,
    is_anthropic_error,
    openai_error_body,
    translate_error_body,
)
from services.protocol_translation.responses import (
    chat_items_to_responses_sse,
    chat_request_to_responses,
    chat_response_to_responses,
    responses_request_to_chat,
    responses_response_to_chat,
    responses_sse_items,
)

__all__ = [
    "CHAT",
    "MESSAGES",
    "OPENAI_FAMILY",
    "PROTOCOLS",
    "RESPONSES",
    "ChatItem",
    "StreamComment",
    "StreamFailure",
    "TranslationError",
    "UpstreamFailure",
    "aggregate_stream",
    "anthropic_error_body",
    "completion_stream",
    "error_details",
    "is_anthropic_error",
    "openai_error_body",
    "strip_unsigned_thinking",
    "translate_error",
    "translate_request",
    "translate_response",
    "translate_stream",
]

_REQUEST_TO_CHAT: dict[str, Callable[[Mapping[str, Any]], dict]] = {
    RESPONSES: responses_request_to_chat,
    MESSAGES: messages_request_to_chat,
}
_REQUEST_FROM_CHAT: dict[str, Callable[[Mapping[str, Any]], dict]] = {
    RESPONSES: chat_request_to_responses,
    MESSAGES: chat_request_to_messages,
}
_RESPONSE_TO_CHAT: dict[str, Callable[..., dict]] = {
    RESPONSES: responses_response_to_chat,
    MESSAGES: messages_response_to_chat,
}
_RESPONSE_FROM_CHAT: dict[str, Callable[..., dict]] = {
    RESPONSES: chat_response_to_responses,
    MESSAGES: chat_response_to_messages,
}
_STREAM_TO_CHAT: dict[str, Callable[[Iterable[Any]], Iterator[ChatItem]]] = {
    CHAT: chat_sse_items,
    RESPONSES: responses_sse_items,
    MESSAGES: messages_sse_items,
}
_STREAM_FROM_CHAT: dict[str, Callable[..., Iterator[str]]] = {
    CHAT: chat_items_to_sse,
    RESPONSES: chat_items_to_responses_sse,
    MESSAGES: chat_items_to_messages_sse,
}


# Client and upstream bodies are untrusted JSON; a wrong shape is a 400 or 502.
_SHAPE_ERRORS = (TypeError, AttributeError, KeyError, IndexError)


def _check(source: str, target: str) -> None:
    if source not in PROTOCOLS or target not in PROTOCOLS:
        raise ValueError(f"Unknown protocol pair: {source} -> {target}")


def translate_request(payload: Mapping[str, Any], source: str, target: str) -> dict:
    """Translate a request body; raises TranslationError for untranslatable features."""
    _check(source, target)
    if source == target:
        return dict(payload)
    try:
        chat = dict(payload) if source == CHAT else _REQUEST_TO_CHAT[source](payload)
        return chat if target == CHAT else _REQUEST_FROM_CHAT[target](chat)
    except _SHAPE_ERRORS as error:
        raise TranslationError("The request body has an invalid shape for this protocol") from error


def translate_response(
    payload: Mapping[str, Any],
    source: str,
    target: str,
    *,
    model: str | None = None,
    request: Mapping[str, Any] | None = None,
) -> dict:
    """Translate a complete (non-streaming) success body."""
    _check(source, target)
    if source == target:
        return dict(payload)
    try:
        chat = dict(payload) if source == CHAT else _RESPONSE_TO_CHAT[source](payload, model=model)
        if target == CHAT:
            return {**chat, "model": model} if model else chat
        return _RESPONSE_FROM_CHAT[target](chat, model=model, request=request)
    except _SHAPE_ERRORS as error:
        raise UpstreamFailure("The upstream response could not be translated") from error


def translate_stream(
    chunks: Iterable[Any],
    source: str,
    target: str,
    *,
    model: str | None = None,
    request: Mapping[str, Any] | None = None,
) -> Iterator[str]:
    """Translate an SSE body event by event; always ends with a terminal event."""
    _check(source, target)
    items = guarded_items(_STREAM_TO_CHAT[source](chunks))
    return _STREAM_FROM_CHAT[target](items, model=model, request=request)


def completion_stream(
    payload: Mapping[str, Any],
    source: str,
    target: str,
    *,
    model: str | None = None,
    request: Mapping[str, Any] | None = None,
) -> Iterator[str]:
    """Replay a complete success body as the target protocol's stream."""
    _check(source, target)
    chat = translate_response(payload, source, CHAT)
    try:
        items = list(chat_completion_items(chat))
    except _SHAPE_ERRORS as error:
        raise UpstreamFailure("The upstream response could not be translated") from error
    return _STREAM_FROM_CHAT[target](items, model=model, request=request)


def aggregate_stream(
    chunks: Iterable[Any],
    source: str,
    target: str,
    *,
    model: str | None = None,
    request: Mapping[str, Any] | None = None,
) -> dict:
    """Fold an SSE body into one target body; raises UpstreamFailure if it failed."""
    _check(source, target)
    chat = aggregate_chat_items(guarded_items(_STREAM_TO_CHAT[source](chunks)))
    return translate_response(chat, CHAT, target, model=model, request=request)


def translate_error(body: Any, status: int, source: str, target: str) -> Any:
    """Re-shape an error body for the target protocol's error envelope."""
    _check(source, target)
    return translate_error_body(body, status, source, target)
