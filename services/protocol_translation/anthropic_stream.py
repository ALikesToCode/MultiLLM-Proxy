"""Convert native Anthropic Messages SSE into Chat Completions items."""

from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from services.protocol_translation.anthropic_continuation import NativeContent

from services.protocol_translation.anthropic_usage import (
    STOP_TO_FINISH,
    anthropic_usage_to_chat,
)
from services.protocol_translation.common import (
    ChatItem,
    StreamComment,
    StreamFailure,
    as_mapping,
    chat_chunk,
    comment_item,
    dumps,
    event_json,
    iter_events,
    new_id,
    unix_time,
)


def _chat_id(value: Any) -> str:
    return (
        f"chatcmpl-{value}" if isinstance(value, str) and value else new_id("chatcmpl")
    )


def messages_sse_items(chunks: Iterable[Any]) -> Iterator[ChatItem]:
    state: dict[str, Any] = {
        "id": new_id("chatcmpl"),
        "model": "",
        "created": unix_time(),
        "started": False,
        "usage": {},
        "stop_reason": None,
    }
    blocks: dict[Any, dict] = {}
    tool_count = 0
    native_content = NativeContent()

    def chunk(
        delta: dict | None = None, finish: str | None = None, usage: dict | None = None
    ) -> list[dict]:
        emitted = []
        if not state["started"]:
            state["started"] = True
            emitted.append(
                chat_chunk(
                    state["id"],
                    state["model"],
                    state["created"],
                    {"role": "assistant", "content": ""},
                )
            )
        if delta is not None or finish is not None:
            emitted.append(
                chat_chunk(
                    state["id"], state["model"], state["created"], delta, finish, usage
                )
            )
        return emitted

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
        data = event_json(event)
        if data is None:
            yield StreamFailure(
                "The upstream stream sent an unreadable event.", interrupted=True
            )
            return
        kind = data.get("type") or event.event
        native_content.observe({**data, "type": kind})
        if kind == "message_start":
            message = as_mapping(data.get("message"))
            if message.get("id"):
                state["id"] = _chat_id(message["id"])
            state["model"] = message.get("model") or state["model"]
            if isinstance(message.get("usage"), Mapping):
                state["usage"].update(message["usage"])
            yield from chunk()
        elif kind == "content_block_start":
            block = as_mapping(data.get("content_block"))
            index = data.get("index")
            block_type = block.get("type")
            if block_type == "tool_use":
                blocks[index] = {
                    "kind": "tool",
                    "tool": tool_count,
                    "streamed": False,
                    "input": block.get("input"),
                }
                tool_count += 1
                yield from chunk(
                    {
                        "tool_calls": [
                            {
                                "index": blocks[index]["tool"],
                                "id": str(block.get("id") or new_id("toolu")),
                                "type": "function",
                                "function": {
                                    "name": str(block.get("name") or ""),
                                    "arguments": "",
                                },
                            }
                        ]
                    }
                )
            elif block_type == "text":
                blocks[index] = {"kind": "text"}
                if block.get("text"):
                    yield from chunk({"content": block["text"]})
            elif block_type == "thinking":
                blocks[index] = {"kind": "thinking"}
                if block.get("thinking"):
                    yield from chunk({"reasoning_content": block["thinking"]})
            else:
                blocks[index] = {"kind": "other"}
        elif kind == "content_block_delta":
            block = blocks.get(data.get("index"), {})
            delta = as_mapping(data.get("delta"))
            delta_type = delta.get("type")
            if delta_type == "text_delta" and delta.get("text"):
                yield from chunk({"content": delta["text"]})
            elif delta_type == "thinking_delta" and delta.get("thinking"):
                yield from chunk({"reasoning_content": delta["thinking"]})
            elif delta_type == "input_json_delta" and block.get("kind") == "tool":
                partial = delta.get("partial_json") or ""
                if partial:
                    block["streamed"] = True
                    yield from chunk(
                        {
                            "tool_calls": [
                                {
                                    "index": block["tool"],
                                    "function": {"arguments": partial},
                                }
                            ]
                        }
                    )
        elif kind == "content_block_stop":
            block = blocks.get(data.get("index"), {})
            if (
                block.get("kind") == "tool"
                and not block["streamed"]
                and block.get("input")
            ):
                # Some compatible servers send the whole input at block start.
                yield from chunk(
                    {
                        "tool_calls": [
                            {
                                "index": block["tool"],
                                "function": {"arguments": dumps(block["input"])},
                            }
                        ]
                    }
                )
        elif kind == "message_delta":
            delta = as_mapping(data.get("delta"))
            if delta.get("stop_reason"):
                state["stop_reason"] = delta["stop_reason"]
            if isinstance(data.get("usage"), Mapping):
                state["usage"].update(
                    {k: v for k, v in data["usage"].items() if v is not None}
                )
        elif kind == "message_stop":
            finish = STOP_TO_FINISH.get(
                state["stop_reason"], "tool_calls" if tool_count else "stop"
            )
            extra = native_content.extra() if tool_count else None
            if extra:
                yield from chunk({"tool_calls": [{"index": 0, "extra_content": extra}]})
            yield from chunk(
                finish=finish, usage=anthropic_usage_to_chat(state["usage"])
            )
            return
        elif kind == "ping":
            yield StreamComment("ping")
        elif kind == "error":
            error = as_mapping(data.get("error"))
            yield StreamFailure(
                str(error.get("message") or "The upstream provider reported an error."),
                str(error.get("type") or "api_error"),
            )
            return
    yield StreamFailure(interrupted=True)
