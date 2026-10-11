import copy
import json

import pytest

from services.intelligence_stream import ChatStream
from services.protocol_translation import (
    CHAT,
    MESSAGES,
    RESPONSES,
    TranslationError,
    aggregate_stream,
    translate_request,
    translate_response,
    translate_stream,
)
from streaming.sse import iter_sse_events
from services.protocol_translation.anthropic import messages_sse_items
from services.protocol_translation.common import (
    UpstreamFailure,
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


def native_frames(content=CONTENT):
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
    for index, block in enumerate(content):
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
            arguments = json.dumps(block["input"], separators=(",", ":"))
            split = len(arguments) // 2
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
                            "partial_json": arguments[:split],
                        },
                    },
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": arguments[split:],
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


def test_implicit_text_block_survives_signed_tool_continuation():
    frames = []
    for frame in native_frames():
        event = json.loads(frame.decode()[6:])
        if event.get("type") == "content_block_start" and event.get("index") == 2:
            event = {
                "type": "content_block_delta",
                "index": 2,
                "delta": {"type": "text_delta", "text": CONTENT[2]["text"]},
            }
        frames.append(f"data: {json.dumps(event)}\n\n".encode())
    assistant = aggregate_chat_items(messages_sse_items(frames))["choices"][0][
        "message"
    ]
    rebuilt = translate_request(continuation_request(assistant), CHAT, MESSAGES)
    assert rebuilt["messages"][1]["content"] == CONTENT


@pytest.mark.parametrize(
    "kind", ["thinking_delta", "signature_delta", "input_json_delta"]
)
def test_signed_or_tool_delta_requires_its_native_block_start(kind):
    content = anthropic_continuation.NativeContent()
    with pytest.raises(ValueError, match="block delta"):
        content.observe(
            {"type": "content_block_delta", "index": 0, "delta": {"type": kind}}
        )


def test_implicit_text_delta_retains_continuation_byte_limit(monkeypatch):
    monkeypatch.setattr(anthropic_continuation, "MAX_CONTINUATION_BYTES", 8)
    content = anthropic_continuation.NativeContent()
    with pytest.raises(ValueError, match="limit"):
        content.observe(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "ok"},
            }
        )


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


def responses_continuation(response):
    return {
        "model": "claude-haiku-5-5",
        "input": [
            {"role": "user", "content": "Weather?"},
            *response["output"],
            *[
                {
                    "type": "function_call_output",
                    "call_id": item["call_id"],
                    "output": "Sunny",
                }
                for item in response["output"]
                if item["type"] == "function_call"
            ],
        ],
    }


def test_responses_json_preserves_complete_signed_tool_continuation():
    response = translate_response(native_response(), MESSAGES, RESPONSES)
    call = next(item for item in response["output"] if item["type"] == "function_call")
    assert call["extra_content"]["anthropic"]["content"] == CONTENT
    rebuilt = translate_request(responses_continuation(response), RESPONSES, MESSAGES)
    assert rebuilt["messages"][1]["content"] == CONTENT
    chat = translate_response(response, RESPONSES, CHAT)
    assistant = chat["choices"][0]["message"]
    rebuilt = translate_request(continuation_request(assistant), CHAT, MESSAGES)
    assert rebuilt["messages"][1]["content"] == CONTENT


def test_chat_request_to_responses_preserves_signed_function_call_metadata():
    assistant = translate_response(native_response(), MESSAGES, CHAT)["choices"][0][
        "message"
    ]
    request = translate_request(continuation_request(assistant), CHAT, RESPONSES)
    rebuilt = translate_request(request, RESPONSES, MESSAGES)
    assert rebuilt["messages"][1]["content"] == CONTENT


@pytest.mark.parametrize("parallel", [False, True])
def test_responses_stream_completed_output_preserves_signed_tool_continuation(parallel):
    content = copy.deepcopy(CONTENT)
    if parallel:
        content.append(
            {
                "type": "tool_use",
                "id": "toolu_2",
                "name": "weather",
                "input": {"city": "Rome"},
            }
        )
    frames = list(translate_stream(native_frames(content), MESSAGES, RESPONSES))
    events = [json.loads(event.data) for event in iter_sse_events(frames) if event.data]
    response = next(event["response"] for event in events if event["type"] == "response.completed")
    call = next(item for item in response["output"] if item["type"] == "function_call")
    assert call["extra_content"]["anthropic"]["content"] == content
    if not parallel:
        done = next(
            event["item"]
            for event in events
            if event["type"] == "response.output_item.done"
            and event["item"]["type"] == "function_call"
        )
        assert done["extra_content"] == call["extra_content"]
    rebuilt = translate_request(responses_continuation(response), RESPONSES, MESSAGES)
    assert rebuilt["messages"][1]["content"] == content
    chat = aggregate_stream(frames, RESPONSES, CHAT)
    assistant = chat["choices"][0]["message"]
    request = continuation_request(assistant)
    if parallel:
        request["messages"].append({"role": "tool", "tool_call_id": "toolu_2", "content": "Sunny"})
    assert translate_request(request, CHAT, MESSAGES)["messages"][1]["content"] == content


@pytest.mark.parametrize("mutation", ["signature", "arguments", "text"])
def test_changed_responses_continuation_fails_closed(mutation):
    response = translate_response(native_response(), MESSAGES, RESPONSES)
    call = next(item for item in response["output"] if item["type"] == "function_call")
    if mutation == "signature":
        call["extra_content"]["anthropic"]["content"][0]["signature"] = 123
    elif mutation == "arguments":
        call["arguments"] = '{"city":"London"}'
    else:
        next(item for item in response["output"] if item["type"] == "message")["content"][0][
            "text"
        ] = "Changed"
    with pytest.raises(TranslationError):
        translate_request(responses_continuation(response), RESPONSES, MESSAGES)


@pytest.mark.parametrize("source", [CHAT, RESPONSES])
def test_responses_translation_rejects_invalid_upstream_continuation(source):
    response = translate_response(native_response(), MESSAGES, source)
    if source == CHAT:
        call = response["choices"][0]["message"]["tool_calls"][0]
        target = RESPONSES
    else:
        call = next(item for item in response["output"] if item["type"] == "function_call")
        target = CHAT
    call["extra_content"]["anthropic"]["content"][0]["signature"] = 123
    with pytest.raises(UpstreamFailure, match="continuation"):
        translate_response(response, source, target)


def test_responses_stream_rejects_invalid_terminal_continuation():
    frames = list(translate_stream(native_frames(), MESSAGES, RESPONSES))
    corrupted = []
    for event in iter_sse_events(frames):
        data = json.loads(event.data)
        if data["type"] == "response.completed":
            call = next(
                item for item in data["response"]["output"] if item["type"] == "function_call"
            )
            call["extra_content"]["anthropic"]["content"][0]["signature"] = 123
        corrupted.append(f"data: {json.dumps(data)}\n\n")
    with pytest.raises(UpstreamFailure):
        aggregate_stream(corrupted, RESPONSES, CHAT)
