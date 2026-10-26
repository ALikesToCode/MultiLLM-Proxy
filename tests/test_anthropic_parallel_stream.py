"""Signed parallel tool turns, including tools without argument fragments."""

import json
import logging

import pytest

from services.protocol_translation import (
    CHAT,
    MESSAGES,
    translate_request,
    translate_stream,
)
from services.protocol_translation.anthropic import messages_sse_items
from services.protocol_translation.common import (
    StreamFailure,
    aggregate_chat_items,
    guarded_items,
)
from streaming.sse import iter_sse_events

CONTENT = [
    {"type": "thinking", "thinking": "", "signature": "opaque-signature"},
    {
        "type": "tool_use",
        "id": "toolu_tokyo",
        "name": "get_current_time",
        "input": {"timezone": "Asia/Tokyo"},
    },
    {
        "type": "tool_use",
        "id": "toolu_london",
        "name": "get_current_time",
        "input": {"timezone": "Europe/London"},
    },
    {
        "type": "tool_use",
        "id": "toolu_reminders",
        "name": "list_reminders",
        "input": {},
    },
]


def parallel_frames(empty_fragments, interleaved=False):
    events = [
        {
            "type": "message_start",
            "message": {
                "id": "msg_parallel",
                "model": "claude-haiku-5-5",
                "usage": {"input_tokens": 5, "output_tokens": 0},
            },
        },
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "thinking", "thinking": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "signature_delta", "signature": "opaque-signature"},
        },
    ]
    if not interleaved:
        events.append({"type": "content_block_stop", "index": 0})
    for index, block in enumerate(CONTENT[1:], 1):
        events.append(
            {
                "type": "content_block_start",
                "index": index,
                "content_block": {**block, "input": {}},
            }
        )
        fragments = (
            [json.dumps(block["input"])[:8], json.dumps(block["input"])[8:]]
            if block["input"]
            else empty_fragments
        )
        events.extend(
            {
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "input_json_delta", "partial_json": fragment},
            }
            for fragment in fragments
        )
        if not interleaved:
            events.append({"type": "content_block_stop", "index": index})
    if interleaved:
        events.extend(
            {"type": "content_block_stop", "index": index} for index in (2, 0, 3, 1)
        )
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
    return [
        f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
        for event in events
    ]


@pytest.mark.parametrize("interleaved", [False, True])
@pytest.mark.parametrize("empty_fragments", [[], [""], ["", ""], ["{}"]])
def test_signed_parallel_tools_stream_to_chat(empty_fragments, interleaved):
    frames = parallel_frames(empty_fragments, interleaved)
    # Exercise the unguarded translator too, so failures expose their real type.
    items = list(messages_sse_items(frames))
    assert not any(isinstance(item, StreamFailure) for item in items)
    output = list(translate_stream(frames, MESSAGES, CHAT))
    events = list(iter_sse_events(output))
    assert events[-1].is_done
    chunks = [
        json.loads(event.data) for event in events if event.data and not event.is_done
    ]
    assert not any("error" in chunk for chunk in chunks)
    starts = [
        call
        for chunk in chunks
        for call in chunk["choices"][0]["delta"].get("tool_calls", [])
        if "id" in call
    ]
    assert [(call["index"], call["id"]) for call in starts] == [
        (index, block["id"]) for index, block in enumerate(CONTENT[1:])
    ]
    completion = aggregate_chat_items(chunks)
    assert completion["choices"][0]["finish_reason"] == "tool_calls"
    assert completion["usage"] == {
        "prompt_tokens": 5,
        "completion_tokens": 8,
        "total_tokens": 13,
    }
    assistant = completion["choices"][0]["message"]
    calls = assistant["tool_calls"]
    assert [json.loads(call["function"]["arguments"]) for call in calls] == [
        block["input"] for block in CONTENT[1:]
    ]
    assert calls[0]["extra_content"]["anthropic"]["content"] == CONTENT
    assert all("extra_content" not in call for call in calls[1:])
    request = {
        "model": "claude-haiku-5-5",
        "messages": [
            {"role": "user", "content": "Times and reminders?"},
            assistant,
            *[
                {"role": "tool", "tool_call_id": call["id"], "content": "ok"}
                for call in calls
            ],
        ],
    }
    assert (
        translate_request(request, CHAT, MESSAGES)["messages"][1]["content"] == CONTENT
    )


@pytest.mark.parametrize("fragments", [["{"], [" "]])
def test_nonempty_invalid_arguments_still_fail_closed(fragments, caplog):
    with caplog.at_level(logging.WARNING):
        output = list(translate_stream(parallel_frames(fragments), MESSAGES, CHAT))
    events = list(iter_sse_events(output))
    chunks = [
        json.loads(event.data) for event in events if event.data and not event.is_done
    ]
    assert events[-1].is_done
    assert (
        chunks[-1]["error"]["message"] == "The upstream stream could not be translated."
    )
    assert not any(
        choice.get("finish_reason")
        for chunk in chunks
        for choice in chunk.get("choices", [])
    )
    assert "type=JSONDecodeError" in caplog.text


@pytest.mark.parametrize(
    "error_type", [TypeError, AttributeError, KeyError, IndexError, ValueError]
)
def test_stream_guard_logs_only_exception_type(error_type, caplog):
    def broken_items():
        yield {"choices": []}
        raise error_type("private upstream content")

    with caplog.at_level(logging.WARNING):
        items = list(guarded_items(broken_items()))
    assert items == [
        {"choices": []},
        StreamFailure("The upstream stream could not be translated."),
    ]
    record = caplog.records[-1]
    assert (
        record.getMessage()
        == f"Upstream stream translation failed type={error_type.__name__}"
    )
    assert record.exc_info is None
    assert record.stack_info is None
    assert "private upstream content" not in caplog.text
