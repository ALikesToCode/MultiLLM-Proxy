"""Chat Completions content parts keep their `cache_control` breakpoints in Messages."""

import json
import os
from unittest.mock import patch

import pytest

from services.protocol_translation.anthropic import chat_request_to_messages
from services.protocol_translation.common import TranslationError
from tests.test_advisor_tool import advised_message, json_reply
from tests.unified_api_test_case import UnifiedApiTestCase

MARK = {"type": "ephemeral"}
HOUR = {"type": "ephemeral", "ttl": "1h"}


def translate(messages, **extra):
    return chat_request_to_messages({"model": "claude-haiku-5-5", "messages": messages, **extra})


def marks(body):
    found = [block.get("cache_control") for block in body["system"]] if isinstance(body.get("system"), list) else []
    for turn in body["messages"]:
        for block in turn["content"]:
            found.append(block.get("cache_control"))
            if block.get("type") == "tool_result" and isinstance(block.get("content"), list):
                found.extend(item.get("cache_control") for item in block["content"])
    return [mark for mark in found if mark]


def test_user_parts_keep_their_breakpoints():
    image = "data:image/png;base64,iVBORw0KGgo="
    body = translate([{"role": "user", "content": [
        {"type": "text", "text": "A long synthetic document", "cache_control": HOUR},
        {"type": "image_url", "image_url": {"url": image}, "cache_control": MARK},
        {"type": "file", "file": {"file_data": "data:application/pdf;base64,JVBERi0=", "filename": "a.pdf"},
         "cache_control": MARK},
        {"type": "text", "text": "A synthetic question"}]}])
    blocks = body["messages"][0]["content"]
    assert [block["type"] for block in blocks] == ["text", "image", "document", "text"]
    assert [block.get("cache_control") for block in blocks] == [HOUR, MARK, MARK, None]
    assert blocks[0]["text"] == "A long synthetic document"


def test_a_system_breakpoint_splits_the_system_prompt_into_blocks():
    body = translate([{"role": "system", "content": [{"type": "text", "text": "Synthetic rules", "cache_control": MARK},
                                                      {"type": "text", "text": "More rules"}]},
                      {"role": "developer", "content": "A developer note"},
                      {"role": "user", "content": "A synthetic question"}], response_format={"type": "json_object"})
    assert [block["text"] for block in body["system"]][:3] == ["Synthetic rules", "More rules", "A developer note"]
    assert body["system"][0]["cache_control"] == MARK
    assert all("cache_control" not in block for block in body["system"][1:])
    assert "JSON" in body["system"][-1]["text"]


def test_a_system_prompt_without_breakpoints_stays_one_string():
    body = translate([{"role": "system", "content": [{"type": "text", "text": "One"}, {"type": "text", "text": "Two"}]},
                      {"role": "system", "content": "Three"}, {"role": "user", "content": "A synthetic question"}])
    assert body["system"] == "OneTwo\n\nThree"


def test_assistant_and_tool_parts_keep_their_breakpoints():
    body = translate([
        {"role": "user", "content": "A synthetic question"},
        {"role": "assistant", "content": [{"type": "text", "text": "Calling", "cache_control": MARK}],
         "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": [{"type": "text", "text": "Found", "cache_control": MARK}]},
    ])
    assistant, tool = body["messages"][1]["content"], body["messages"][2]["content"][0]
    assert assistant[0] == {"type": "text", "text": "Calling", "cache_control": MARK}
    assert assistant[1]["type"] == "tool_use"
    assert tool["content"] == [{"type": "text", "text": "Found", "cache_control": MARK}]


def test_only_the_last_four_breakpoints_are_kept():
    messages = [{"role": "system", "content": [{"type": "text", "text": "Rules", "cache_control": MARK}]}]
    for turn in range(6):
        role = "user" if turn % 2 == 0 else "assistant"
        messages.append({"role": role, "content": [{"type": "text", "text": f"Turn {turn}", "cache_control": MARK}]})
    body = translate(messages)
    assert len(marks(body)) == 4
    assert "cache_control" not in body["system"][0]
    assert [bool(turn["content"][0].get("cache_control")) for turn in body["messages"]] == [False, False, True, True, True, True]


@pytest.mark.parametrize("marker", [{"type": "persistent"}, {"type": "ephemeral", "ttl": "2h"},
                                    {"type": "ephemeral", "ttl": ["1h"]},
                                    {"type": "ephemeral", "scope": "global"}, "ephemeral"])
@pytest.mark.parametrize("role", ["user", "system", "assistant", "tool"])
def test_an_invalid_breakpoint_is_refused(marker, role):
    message = {"role": role, "content": [{"type": "text", "text": "x", "cache_control": marker}]}
    calls = [{"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function",
                                                   "function": {"name": "lookup", "arguments": "{}"}}]}]
    history = [{"role": "user", "content": "q"}, *(calls if role == "tool" else []),
               {**message, "tool_call_id": "call_1"} if role == "tool" else message, {"role": "user", "content": "q"}]
    with pytest.raises(TranslationError, match="cache_control"):
        translate(history)


def test_a_breakpoint_on_a_part_claude_gets_no_block_for_is_still_checked():
    image = {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}
    with pytest.raises(TranslationError, match="cache_control"):
        translate([{"role": "system", "content": [{"type": "text", "text": "S"}, {**image, "cache_control": {"type": "bogus"}}]},
                   {"role": "user", "content": "q"}])


def test_a_marked_system_prompt_keeps_every_part_the_unmarked_one_joins():
    body = translate([{"role": "system", "content": [{"text": "Untyped rules"},
                                                      {"type": "text", "text": "Typed", "cache_control": MARK}]},
                      {"role": "user", "content": "q"}])
    assert [block["text"] for block in body["system"]] == ["Untyped rules", "Typed"]


def test_breakpoints_inside_tool_results_count_toward_the_limit():
    messages = [{"role": "user", "content": [{"type": "text", "text": "q", "cache_control": MARK}]}]
    for turn in range(4):
        messages.append({"role": "assistant", "tool_calls": [{"id": f"call_{turn}", "type": "function",
                                                              "function": {"name": "lookup", "arguments": "{}"}}]})
        messages.append({"role": "tool", "tool_call_id": f"call_{turn}",
                         "content": [{"type": "text", "text": f"r{turn}", "cache_control": MARK}]})
    body = translate(messages)
    assert "cache_control" not in body["messages"][0]["content"][0]
    assert [bool(turn["content"][0]["content"][0].get("cache_control")) for turn in body["messages"][2::2]] == [True] * 4


def test_the_caller_payload_is_left_unchanged():
    messages = [{"role": "user", "content": [{"type": "text", "text": f"t{n}", "cache_control": MARK}]} for n in range(6)]
    payload = {"model": "claude-haiku-5-5", "messages": messages}
    saved = json.loads(json.dumps(payload))
    assert len(marks(chat_request_to_messages(payload))) == 4
    assert payload == saved


def test_a_null_breakpoint_is_no_breakpoint():
    body = translate([{"role": "user", "content": [{"type": "text", "text": "x", "cache_control": None}]}])
    assert marks(body) == []


class ChatCacheControlRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["ANTHROPIC_API_KEY"] = "anthropic-provider-key"

    def test_breakpoints_reach_claude_and_replace_the_gateway_markers(self):
        messages = [{"role": "system", "content": [{"type": "text", "text": "Synthetic rules", "cache_control": MARK}]},
                    {"role": "user", "content": [{"type": "text", "text": "A synthetic question", "cache_control": MARK}]}]
        for path in ("/v1/chat/completions", "/lean/v1/chat/completions"):
            with self.subTest(path=path), patch.object(self.app_module.ProxyService, "make_request",
                                                       return_value=json_reply(advised_message())) as send:
                response = self.client.post(path, json={"model": "anthropic:claude-haiku-5-5", "messages": messages},
                                            headers={"Authorization": "Bearer admin-test-key"})
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                body = json.loads(send.call_args.kwargs["data"])
                self.assertEqual(body["system"][0]["cache_control"], MARK)
                self.assertEqual(body["messages"][-1]["content"][0]["cache_control"], MARK)
                self.assertNotIn("cache_control", body)
                self.assertEqual(len(marks(body)), 2)
