"""Shared vocabulary for protocol translation, with Chat Completions as the pivot.

Streams are translated through a sequence of pivot items: Chat Completions
chunk dictionaries, `StreamComment` keep-alives and at most one terminal
`StreamFailure`. Each producer yields items as upstream events arrive, and each
writer turns items into its protocol's SSE frames, so no stream is buffered.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Union

from streaming.sse import SSEEvent, iter_sse_events

CHAT = "chat"
RESPONSES = "responses"
MESSAGES = "messages"
PROTOCOLS = frozenset({CHAT, RESPONSES, MESSAGES})
# Chat Completions and Responses share OpenAI's error envelope.
OPENAI_FAMILY = frozenset({CHAT, RESPONSES})

INTERRUPTED_MESSAGE = (
    "The upstream stream ended before its final event; the response is incomplete."
)
_TOOL_ID_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")
_DATA_URL = re.compile(r"^data:([^;,]+)?(?:;[^,]*)?;base64,(.*)$", re.DOTALL)


class TranslationError(ValueError):
    """A request feature that the target protocol cannot represent statelessly."""

    def __init__(self, message: str, *, param: str | None = None):
        super().__init__(message)
        self.message = message
        self.param = param


class UpstreamFailure(Exception):
    """A successful HTTP status whose body reports a failed or unreadable result."""

    def __init__(self, message: str, *, error_type: str = "api_error", code: str | None = None):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.code = code


@dataclass(frozen=True)
class StreamComment:
    """An SSE comment such as a provider keep-alive, forwarded as a comment."""

    text: str = "keep-alive"


@dataclass(frozen=True)
class StreamFailure:
    """A terminal stream failure; `interrupted` means no terminal event arrived."""

    message: str = INTERRUPTED_MESSAGE
    error_type: str = "api_error"
    code: str | None = None
    interrupted: bool = False


ChatItem = Union[dict, StreamComment, StreamFailure]


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:24]}"


def unix_time() -> int:
    return int(time.time())


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def sse_data(payload: Any) -> str:
    return f"data: {dumps(payload)}\n\n"


def sse_event(name: str, payload: Any) -> str:
    return f"event: {name}\ndata: {dumps(payload)}\n\n"


def sse_comment(text: str) -> str:
    cleaned = " ".join(str(text or "keep-alive").split())[:120] or "keep-alive"
    return f": {cleaned}\n\n"


def safe_tool_id(value: Any, prefix: str = "toolu") -> str:
    """Anthropic tool IDs allow only [A-Za-z0-9_-]; map others deterministically."""
    if isinstance(value, str) and value.strip():
        return _TOOL_ID_UNSAFE.sub("_", value.strip())[:128]
    return new_id(prefix)


def parse_data_url(url: str) -> tuple[str, str] | None:
    match = _DATA_URL.match(url or "")
    if not match:
        return None
    return (match.group(1) or "application/octet-stream").strip().lower(), match.group(2)


def load_arguments(raw: Any) -> dict:
    """Decode tool-call arguments into the object Messages requires."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        # Keep malformed model output visible instead of silently erasing it.
        return {"_raw_arguments": raw}
    return value if isinstance(value, dict) else {"value": value}


def text_of(value: Any) -> str:
    """Join the text of a string, a text part or a list of text parts."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        text = value.get("text")
        return text if isinstance(text, str) else ""
    if isinstance(value, list):
        return "".join(text_of(item) for item in value)
    return ""


def as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def non_negative_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


# ---------------------------------------------------------------------------
# Usage accounting. The pivot keeps Chat Completions fields plus
# `prompt_tokens_details.cache_write_tokens` so cache writes survive a round trip.


def chat_usage(
    prompt: int,
    completion: int,
    *,
    cached: int = 0,
    cache_write: int = 0,
    reasoning: int = 0,
) -> dict:
    usage: dict[str, Any] = {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
    }
    details: dict[str, int] = {}
    if cached:
        details["cached_tokens"] = cached
    if cache_write:
        details["cache_write_tokens"] = cache_write
    if details:
        usage["prompt_tokens_details"] = details
    if reasoning:
        usage["completion_tokens_details"] = {"reasoning_tokens": reasoning}
    return usage


def usage_numbers(usage: Any) -> dict[str, int]:
    usage = usage if isinstance(usage, Mapping) else {}
    prompt_details = usage.get("prompt_tokens_details")
    prompt_details = prompt_details if isinstance(prompt_details, Mapping) else {}
    completion_details = usage.get("completion_tokens_details")
    completion_details = completion_details if isinstance(completion_details, Mapping) else {}
    return {
        "prompt": non_negative_int(usage.get("prompt_tokens")),
        "completion": non_negative_int(usage.get("completion_tokens")),
        "cached": non_negative_int(prompt_details.get("cached_tokens")),
        "cache_write": non_negative_int(prompt_details.get("cache_write_tokens")),
        "reasoning": non_negative_int(completion_details.get("reasoning_tokens")),
    }


# ---------------------------------------------------------------------------
# Errors.

_OPENAI_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    402: "insufficient_quota",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    413: "invalid_request_error",
    422: "invalid_request_error",
    429: "rate_limit_error",
}
_ANTHROPIC_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    402: "billing_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    413: "request_too_large",
    422: "invalid_request_error",
    429: "rate_limit_error",
    500: "api_error",
    503: "overloaded_error",
    504: "timeout_error",
    529: "overloaded_error",
}
ANTHROPIC_ERROR_NAMES = frozenset(_ANTHROPIC_ERROR_TYPES.values())
_TYPE_ALIASES = {
    "rate_limit_exceeded": "rate_limit_error",
    "server_error": "api_error",
    "overloaded": "overloaded_error",
    "timeout": "timeout_error",
    "insufficient_quota": "billing_error",
}


def error_details(body: Any, status: int = 502) -> tuple[str, str | None, str | None]:
    """Return (message, type, code) from any known error envelope."""
    if isinstance(body, Mapping):
        error = body.get("error")
        if isinstance(error, Mapping):
            message = error.get("message") or body.get("message")
            error_type = error.get("type")
            code = error.get("code")
            return (
                str(message) if message else f"Upstream request failed with status {status}",
                str(error_type) if isinstance(error_type, str) else None,
                str(code) if code is not None else None,
            )
        if isinstance(error, str):
            message = body.get("message") or error
            return str(message), None, error
        if isinstance(body.get("message"), str):
            return body["message"], None, None
        response = body.get("response")
        if isinstance(response, Mapping) and isinstance(response.get("error"), Mapping):
            return error_details({"error": response["error"]}, status)
    if isinstance(body, str) and body.strip():
        return body.strip()[:2000], None, None
    return f"Upstream request failed with status {status}", None, None


def openai_error_body(
    status: int,
    message: str,
    error_type: str | None = None,
    code: str | None = None,
    param: str | None = None,
) -> dict:
    return {
        "error": {
            "message": message,
            "type": error_type
            or _OPENAI_ERROR_TYPES.get(
                status, "server_error" if status >= 500 else "invalid_request_error"
            ),
            "param": param,
            "code": code,
        }
    }


def anthropic_error_type(status: int, error_type: str | None = None) -> str:
    if error_type in ANTHROPIC_ERROR_NAMES:
        return str(error_type)
    if error_type in _TYPE_ALIASES:
        return _TYPE_ALIASES[str(error_type)]
    if status in _ANTHROPIC_ERROR_TYPES:
        return _ANTHROPIC_ERROR_TYPES[status]
    return "api_error" if status >= 500 else "invalid_request_error"


def anthropic_error_body(
    status: int,
    message: str,
    error_type: str | None = None,
    request_id: str | None = None,
) -> dict:
    body: dict[str, Any] = {
        "type": "error",
        "error": {"type": anthropic_error_type(status, error_type), "message": message},
    }
    if request_id:
        body["request_id"] = request_id
    return body


def is_anthropic_error(body: Any) -> bool:
    return (
        isinstance(body, Mapping)
        and body.get("type") == "error"
        and isinstance(body.get("error"), Mapping)
    )


def translate_error_body(body: Any, status: int, source: str, target: str) -> Any:
    """Re-shape an error body only when it crosses the OpenAI/Anthropic boundary."""
    if target == MESSAGES:
        if is_anthropic_error(body):
            return body
        message, error_type, _ = error_details(body, status)
        request_id = body.get("request_id") if isinstance(body, Mapping) else None
        return anthropic_error_body(status, message, error_type, request_id)
    if source in OPENAI_FAMILY and target in OPENAI_FAMILY:
        return body
    if (
        isinstance(body, Mapping)
        and isinstance(body.get("error"), Mapping)
        and not is_anthropic_error(body)
    ):
        return body
    message, error_type, code = error_details(body, status)
    return openai_error_body(status, message, error_type, code)


# ---------------------------------------------------------------------------
# SSE input.


def iter_events(chunks: Iterable[Any]) -> Iterator[SSEEvent | StreamFailure]:
    """Parse SSE incrementally and turn a broken upstream read into a failure."""
    iterator = iter_sse_events(chunks)
    while True:
        try:
            event = next(iterator)
        except StopIteration:
            return
        except Exception:  # noqa: BLE001 - any transport error ends the stream
            yield StreamFailure(interrupted=True)
            return
        yield event


def event_json(event: SSEEvent) -> dict | None:
    try:
        payload = json.loads(event.data)
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def comment_item(event: SSEEvent) -> StreamComment | None:
    if event.data or not event.comments:
        return None
    return StreamComment(event.comments[-1] or "keep-alive")


# ---------------------------------------------------------------------------
# Chat Completions pivot.


def chat_chunk(
    chunk_id: str,
    model: str | None,
    created: int,
    delta: dict | None = None,
    finish_reason: str | None = None,
    usage: dict | None = None,
) -> dict:
    chunk: dict[str, Any] = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model or "",
        "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
    }
    if usage is not None:
        chunk["usage"] = usage
    return chunk


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _tool_fragment(fragment: Any, position: int) -> dict | None:
    if not isinstance(fragment, Mapping):
        return None
    index = fragment.get("index")
    clean: dict[str, Any] = {
        "index": index if isinstance(index, int) and not isinstance(index, bool) else position
    }
    if _string(fragment.get("id")):
        clean["id"] = fragment["id"]
    if fragment.get("type") == "function":
        clean["type"] = "function"
    function = fragment.get("function")
    if isinstance(function, Mapping):
        clean["function"] = {
            key: function[key]
            for key in ("name", "arguments")
            if _string(function.get(key)) is not None
        }
    return clean


def normalize_chat_chunk(payload: Mapping[str, Any]) -> dict:
    """Keep only well-typed Chat Completions chunk fields, so writers can trust items."""
    choices = []
    raw_choices = payload.get("choices")
    for choice in raw_choices if isinstance(raw_choices, list) else []:
        if not isinstance(choice, Mapping):
            continue
        index = choice.get("index", 0)
        raw_delta = choice.get("delta")
        raw_delta = raw_delta if isinstance(raw_delta, Mapping) else {}
        delta: dict[str, Any] = {}
        for key in ("role", "content", "refusal", "reasoning_content"):
            if _string(raw_delta.get(key)) is not None:
                delta[key] = raw_delta[key]
        if "reasoning_content" not in delta and _string(raw_delta.get("reasoning")):
            delta["reasoning_content"] = raw_delta["reasoning"]
        raw_calls = raw_delta.get("tool_calls")
        calls = [
            fragment
            for fragment in (
                _tool_fragment(item, position)
                for position, item in enumerate(raw_calls if isinstance(raw_calls, list) else [])
            )
            if fragment is not None
        ]
        if calls:
            delta["tool_calls"] = calls
        choices.append(
            {
                "index": index if isinstance(index, int) and not isinstance(index, bool) else 0,
                "delta": delta,
                "finish_reason": _string(choice.get("finish_reason")),
            }
        )
    chunk: dict[str, Any] = {
        "id": _string(payload.get("id")) or "",
        "object": "chat.completion.chunk",
        "created": payload.get("created")
        if isinstance(payload.get("created"), int)
        else unix_time(),
        "model": _string(payload.get("model")) or "",
        "choices": choices,
    }
    if isinstance(payload.get("usage"), Mapping):
        chunk["usage"] = dict(payload["usage"])
    return chunk


def guarded_items(items: Iterable[ChatItem]) -> Iterator[ChatItem]:
    """End with a failure, not an exception, when an upstream event has a bad shape."""
    try:
        yield from items
    except (TypeError, AttributeError, KeyError, IndexError, ValueError):
        yield StreamFailure("The upstream stream could not be translated.")


def chat_sse_items(chunks: Iterable[Any]) -> Iterator[ChatItem]:
    """Pivot items from a Chat Completions SSE body."""
    finished = False
    for event in iter_events(chunks):
        if isinstance(event, StreamFailure):
            yield event
            return
        comment = comment_item(event)
        if comment is not None:
            yield comment
            continue
        if not event.data:
            continue
        if event.is_done:
            if not finished:
                yield StreamFailure(interrupted=True)
            return
        payload = event_json(event)
        if payload is None:
            yield StreamFailure("The upstream stream sent an unreadable event.", interrupted=True)
            return
        if event.event == "error" or "error" in payload:
            message, error_type, code = error_details(payload)
            yield StreamFailure(message, error_type or "api_error", code)
            return
        item = normalize_chat_chunk(payload)
        if any(choice["finish_reason"] for choice in item["choices"]):
            finished = True
        yield item
    if not finished:
        yield StreamFailure(interrupted=True)


def chat_items_to_sse(
    items: Iterable[ChatItem],
    *,
    model: str | None = None,
    request: Mapping[str, Any] | None = None,
) -> Iterator[str]:
    """Write pivot items as Chat Completions SSE, ending with `[DONE]`."""
    del request
    finished = False
    for item in items:
        if isinstance(item, StreamComment):
            yield sse_comment(item.text)
            continue
        if isinstance(item, StreamFailure):
            yield _chat_failure_frame(item)
            yield "data: [DONE]\n\n"
            return
        if model:
            item = {**item, "model": model}
        choices = item.get("choices")
        if isinstance(choices, list) and any(
            isinstance(choice, Mapping) and choice.get("finish_reason") for choice in choices
        ):
            finished = True
        yield sse_data(item)
    if not finished:
        yield _chat_failure_frame(StreamFailure(interrupted=True))
    yield "data: [DONE]\n\n"


def _chat_failure_frame(failure: StreamFailure) -> str:
    return sse_data(
        {
            "error": {
                "message": failure.message,
                "type": "upstream_stream_interrupted"
                if failure.interrupted
                else failure.error_type or "api_error",
                "code": failure.code or ("stream_interrupted" if failure.interrupted else None),
            }
        }
    )


def aggregate_chat_items(items: Iterable[ChatItem]) -> dict:
    """Fold pivot items into one chat.completion, raising on any stream failure."""
    completion_id = new_id("chatcmpl")
    model = ""
    created = unix_time()
    content: list[str] = []
    reasoning: list[str] = []
    refusal: list[str] = []
    calls: dict[int, dict] = {}
    finish = None
    usage = None
    for item in items:
        if isinstance(item, StreamComment):
            continue
        if isinstance(item, StreamFailure):
            raise UpstreamFailure(item.message, error_type=item.error_type, code=item.code)
        completion_id = item.get("id") or completion_id
        model = item.get("model") or model
        created = item.get("created") or created
        if item.get("usage"):
            usage = item["usage"]
        for choice in item.get("choices") or []:
            if not isinstance(choice, Mapping) or choice.get("index", 0) != 0:
                continue
            delta = choice.get("delta") or {}
            if isinstance(delta.get("content"), str):
                content.append(delta["content"])
            if isinstance(delta.get("refusal"), str):
                refusal.append(delta["refusal"])
            thought = delta.get("reasoning_content")
            if not isinstance(thought, str):
                thought = (
                    delta.get("reasoning") if isinstance(delta.get("reasoning"), str) else None
                )
            if thought:
                reasoning.append(thought)
            for fragment in delta.get("tool_calls") or []:
                if not isinstance(fragment, Mapping):
                    continue
                index = fragment.get("index", len(calls))
                call = calls.setdefault(
                    index,
                    {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
                )
                if fragment.get("id"):
                    call["id"] = call["id"] or fragment["id"]
                function = fragment.get("function") or {}
                for key in ("name", "arguments"):
                    if isinstance(function.get(key), str):
                        call["function"][key] += function[key]
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
    message: dict[str, Any] = {"role": "assistant", "content": "".join(content) or None}
    if calls:
        message["tool_calls"] = [calls[index] for index in sorted(calls)]
    if refusal:
        message["refusal"] = "".join(refusal)
    if reasoning:
        message["reasoning_content"] = "".join(reasoning)
    if message["content"] is None and not calls:
        message["content"] = ""
    completion: dict[str, Any] = {
        "id": completion_id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish or "stop"}],
    }
    if usage is not None:
        completion["usage"] = usage
    return completion


def chat_completion_items(completion: Mapping[str, Any]) -> Iterator[ChatItem]:
    """Replay a complete chat.completion as pivot stream items."""
    completion_id = completion.get("id") or new_id("chatcmpl")
    model = completion.get("model") or ""
    created = completion.get("created") or unix_time()
    choices = completion.get("choices") or [{}]
    choice = choices[0] if isinstance(choices[0], Mapping) else {}
    message = choice.get("message") or {}
    yield chat_chunk(completion_id, model, created, {"role": "assistant", "content": ""})
    reasoning = message.get("reasoning_content") or message.get("reasoning")
    if isinstance(reasoning, str) and reasoning:
        yield chat_chunk(completion_id, model, created, {"reasoning_content": reasoning})
    if isinstance(message.get("content"), str) and message["content"]:
        yield chat_chunk(completion_id, model, created, {"content": message["content"]})
    if isinstance(message.get("refusal"), str) and message["refusal"]:
        yield chat_chunk(completion_id, model, created, {"refusal": message["refusal"]})
    for index, call in enumerate(message.get("tool_calls") or []):
        function = call.get("function") or {}
        yield chat_chunk(
            completion_id,
            model,
            created,
            {
                "tool_calls": [
                    {
                        "index": index,
                        "id": call.get("id") or new_id("call"),
                        "type": "function",
                        "function": {
                            "name": function.get("name") or "",
                            "arguments": function.get("arguments") or "",
                        },
                    }
                ]
            },
        )
    yield chat_chunk(
        completion_id,
        model,
        created,
        finish_reason=choice.get("finish_reason") or "stop",
        usage=completion.get("usage"),
    )


def first_chat_choice(completion: Mapping[str, Any]) -> tuple[dict, str | None]:
    choices = completion.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
        return {}, None
    choice = choices[0]
    message = choice.get("message")
    return (dict(message) if isinstance(message, Mapping) else {}), choice.get("finish_reason")


def message_reasoning(message: Mapping[str, Any]) -> str:
    for key in ("reasoning_content", "reasoning"):
        value = message.get(key)
        if isinstance(value, str) and value:
            return value
    return ""
