import copy
import json

import pytest

from services.intelligence_stream import ChatStream
from services.protocol_translation import (
    CHAT,
    MESSAGES,
    TranslationError,
    translate_request,
    translate_response,
)
from services.protocol_translation.anthropic import messages_sse_items
from services.protocol_translation.common import (
    aggregate_chat_items,
    chat_items_to_sse,
    chat_completion_items,
    normalize_chat_chunk,
)
from services.protocol_translation import anthropic_continuation


CONTENT = [
    {"type": "thinking", "thinking": "", "signature": "opaque-signature"},
    {"type": "redacted_thinking", "data": "opaque-redacted-data"},
    {"type": "text", "text": "Calling tool."},
    {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "weather",
        "input": {"city": "Paris"},
    },
]


def native_response(content=CONTENT):
    return {
        "id": "msg_signed",
        "type": "message",
        "role": "assistant",
        "model": "claude-haiku-5-5",
        "content": copy.deepcopy(content),
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 5, "output_tokens": 8},
    }


def continuation_request(message):
    return {
        "model": "claude-haiku-5-5",
        "messages": [
            {"role": "user", "content": "Weather?"},
            message,
            {"role": "tool", "tool_call_id": "toolu_1", "content": "Sunny"},
        ],
    }


def test_nonstream_tool_turn_preserves_complete_unmodified_native_content():
    native = native_response()
    snapshot = copy.deepcopy(native)
    chat = translate_response(native, MESSAGES, CHAT)
    assistant = chat["choices"][0]["message"]
    assert assistant["tool_calls"][0]["extra_content"] == {
        "anthropic": {"content": CONTENT}
    }
    rebuilt = translate_request(continuation_request(assistant), CHAT, MESSAGES)
    assert rebuilt["messages"][1]["content"] == CONTENT
    assert native == snapshot
    assert rebuilt["messages"][2]["content"][0]["tool_use_id"] == "toolu_1"


def native_frames():
    events = [
        {
            "type": "message_start",
            "message": {
                "id": "msg_signed",
                "model": "claude-haiku-5-5",
                "usage": {"input_tokens": 5, "output_tokens": 0},
            },
        }
    ]
    for index, block in enumerate(CONTENT):
        if block["type"] == "thinking":
            events.extend(
                [
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "thinking",
                            "thinking": "",
                            "signature": "",
                        },
                    },
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "signature_delta", "signature": "opaque-"},
                    },
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "signature_delta", "signature": "signature"},
                    },
                ]
            )
        elif block["type"] == "tool_use":
            events.extend(
                [
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {**block, "input": {}},
                    },
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": '{"city":',
                        },
                    },
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": '"Paris"}',
                        },
                    },
                ]
            )
        else:
            events.append(
                {"type": "content_block_start", "index": index, "content_block": block}
            )
        events.append({"type": "content_block_stop", "index": index})
    events.extend(
        [
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 8},
            },
            {"type": "message_stop"},
        ]
    )
    return [f"data: {json.dumps(event)}\n\n".encode() for event in events]


@pytest.mark.parametrize("intelligence", [False, True])
def test_stream_signature_fragments_survive_tool_continuation(intelligence):
    items = list(messages_sse_items(native_frames()))
    if intelligence:
        stream = ChatStream(chat_items_to_sse(items), "anthropic:claude-haiku-5-5")
        list(stream.events())
        assistant = stream.completion()["choices"][0]["message"]
    else:
        assistant = aggregate_chat_items(items)["choices"][0]["message"]
    rebuilt = translate_request(continuation_request(assistant), CHAT, MESSAGES)
    assert rebuilt["messages"][1]["content"] == CONTENT


def test_chat_stream_normalization_and_replay_keep_native_continuation():
    chat = translate_response(native_response(), MESSAGES, CHAT)
    items = [normalize_chat_chunk(item) for item in chat_completion_items(chat)]
    assistant = aggregate_chat_items(items)["choices"][0]["message"]
    assert (
        translate_request(continuation_request(assistant), CHAT, MESSAGES)["messages"][
            1
        ]["content"]
        == CONTENT
    )


@pytest.mark.parametrize(
    "mutation", ["text", "arguments", "name", "id", "signature", "server_tool"]
)
def test_invalid_or_changed_native_continuation_fails_closed(mutation):
    assistant = translate_response(native_response(), MESSAGES, CHAT)["choices"][0][
        "message"
    ]
    call = assistant["tool_calls"][0]
    if mutation == "text":
        assistant["content"] = "Changed"
    elif mutation == "arguments":
        call["function"]["arguments"] = '{"city":"London"}'
    elif mutation == "name":
        call["function"]["name"] = "different"
    elif mutation == "id":
        call["id"] = "different"
    elif mutation == "signature":
        call["extra_content"]["anthropic"]["content"][0]["signature"] = 123
    else:
        call["extra_content"]["anthropic"]["content"].append(
            {"type": "server_tool_use"}
        )
    with pytest.raises(TranslationError):
        translate_request(continuation_request(assistant), CHAT, MESSAGES)


def test_native_continuation_size_is_bounded(monkeypatch):
    monkeypatch.setattr(anthropic_continuation, "MAX_CONTINUATION_BYTES", 8)
    with pytest.raises(ValueError, match="limit"):
        anthropic_continuation.continuation_extra(CONTENT)


def test_plain_tool_calls_do_not_add_native_metadata():
    chat = translate_response(native_response(CONTENT[2:]), MESSAGES, CHAT)
    assert "extra_content" not in chat["choices"][0]["message"]["tool_calls"][0]
