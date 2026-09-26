"""Golden fixtures for Chat Completions <-> Responses <-> Anthropic Messages."""

import json
import unittest

from services.protocol_translation import (
    CHAT,
    MESSAGES,
    RESPONSES,
    TranslationError,
    UpstreamFailure,
    aggregate_stream,
    completion_stream,
    strip_unsigned_thinking,
    translate_error,
    translate_request,
    translate_response,
    translate_stream,
)


def sse(*events):
    """Anthropic/Responses frames: (name, payload) pairs."""
    return [f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode() for name, payload in events]


def chat_sse(*payloads, done=True):
    frames = [f"data: {json.dumps(payload)}\n\n".encode() for payload in payloads]
    if done:
        frames.append(b"data: [DONE]\n\n")
    return frames


def parse_frames(text):
    """Split SSE output into (event, data, comment) tuples."""
    frames = []
    for block in text.split("\n\n"):
        if not block:
            continue
        event = data = comment = None
        for line in block.split("\n"):
            if line.startswith("event: "):
                event = line[len("event: "):]
            elif line.startswith("data: "):
                raw = line[len("data: "):]
                data = raw if raw == "[DONE]" else json.loads(raw)
            elif line.startswith(":"):
                comment = line[1:].strip()
        frames.append((event, data, comment))
    return frames


def chunk(delta=None, finish=None, usage=None, model="up-model"):
    payload = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": model,
        "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish}],
    }
    if usage is not None:
        payload["usage"] = usage
    return payload


ANTHROPIC_TOOL_STREAM = sse(
    ("message_start", {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x", "content": [], "usage": {"input_tokens": 20, "cache_read_input_tokens": 5, "output_tokens": 1}}}),
    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "Plan."}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "sig"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
    ("ping", {"type": "ping"}),
    ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "Checking"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 1}),
    ("content_block_start", {"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use", "id": "toolu_7", "name": "get_weather", "input": {}}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": "{\"city\":"}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": " \"Paris\"}"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 2}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 30}}),
    ("message_stop", {"type": "message_stop"}),
)

CHAT_TOOL_STREAM = chat_sse(
    chunk({"role": "assistant", "content": ""}),
    chunk({"reasoning_content": "Think"}),
    chunk({"content": "Hi"}),
    chunk({"content": " there"}),
    chunk({"tool_calls": [{"index": 0, "id": "functions.get_weather:0", "type": "function", "function": {"name": "get_weather", "arguments": ""}}]}),
    chunk({"tool_calls": [{"index": 0, "function": {"arguments": "{\"city\":\"Paris\"}"}}]}),
    chunk(finish="tool_calls"),
    {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1, "model": "up-model", "choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20, "prompt_tokens_details": {"cached_tokens": 2}}},
)


class MessagesToChatRequestTest(unittest.TestCase):
    def test_golden_request_with_system_images_tools_and_thinking(self):
        chat = translate_request(
            {
                "model": "opencode:kimi-k2.6",
                "system": [{"type": "text", "text": "Be terse.", "cache_control": {"type": "ephemeral"}}],
                "max_tokens": 1024,
                "temperature": 0.2,
                "stop_sequences": ["END"],
                "metadata": {"user_id": "claude-code-user"},
                "thinking": {"type": "enabled", "budget_tokens": 8000},
                "tools": [{"name": "get_weather", "description": "Weather", "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}}],
                "tool_choice": {"type": "auto", "disable_parallel_tool_use": True},
                "stream": True,
                "messages": [
                    {"role": "user", "content": [
                        {"type": "text", "text": "Weather?"},
                        {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": "QUJD"}},
                        {"type": "image", "source": {"type": "url", "url": "https://img.example/a.png"}},
                    ]},
                    {"role": "assistant", "content": [
                        {"type": "thinking", "thinking": "Need a tool.", "signature": "sig"},
                        {"type": "text", "text": "Checking."},
                        {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Paris"}},
                    ]},
                    {"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "Sunny"}]},
                        {"type": "text", "text": "Thanks"},
                    ]},
                ],
            },
            MESSAGES,
            CHAT,
        )
        self.assertEqual(
            chat,
            {
                "model": "opencode:kimi-k2.6",
                "messages": [
                    {"role": "system", "content": "Be terse."},
                    {"role": "user", "content": [
                        {"type": "text", "text": "Weather?"},
                        {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,QUJD"}},
                        {"type": "image_url", "image_url": {"url": "https://img.example/a.png"}},
                    ]},
                    {
                        "role": "assistant",
                        "content": "Checking.",
                        "tool_calls": [{"id": "toolu_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}],
                        "reasoning_content": "Need a tool.",
                    },
                    {"role": "tool", "tool_call_id": "toolu_1", "content": "Sunny"},
                    {"role": "user", "content": "Thanks"},
                ],
                "max_tokens": 1024,
                "temperature": 0.2,
                "stop": ["END"],
                "stream": True,
                "stream_options": {"include_usage": True},
                "tools": [{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}, "description": "Weather"}}],
                "tool_choice": "auto",
                "parallel_tool_calls": False,
                "reasoning_effort": "medium",
            },
        )

    def test_tool_choice_and_effort_mappings(self):
        base = {"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}], "tools": [{"name": "f", "input_schema": {"type": "object"}}]}
        for choice, expected in [
            ({"type": "any"}, "required"),
            ({"type": "none"}, "none"),
            ({"type": "tool", "name": "f"}, {"type": "function", "function": {"name": "f"}}),
        ]:
            with self.subTest(choice=choice):
                self.assertEqual(translate_request({**base, "tool_choice": choice}, MESSAGES, CHAT)["tool_choice"], expected)
        effort = translate_request({**base, "output_config": {"effort": "max"}}, MESSAGES, CHAT)
        self.assertEqual(effort["reasoning_effort"], "xhigh")
        schema = translate_request({**base, "output_config": {"format": {"type": "json_schema", "schema": {"type": "object"}}}}, MESSAGES, CHAT)
        self.assertEqual(schema["response_format"], {"type": "json_schema", "json_schema": {"name": "output", "schema": {"type": "object"}, "strict": True}})
        self.assertNotIn("user", schema, "free pools reject `user`, so metadata is not mapped")

    def test_tool_result_images_follow_the_tool_message(self):
        chat = translate_request(
            {"model": "m", "max_tokens": 5, "messages": [
                {"role": "user", "content": "shot"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "screenshot", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "is_error": True, "content": [
                    {"type": "text", "text": "partial"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AA=="}},
                ]}]},
            ]},
            MESSAGES,
            CHAT,
        )
        self.assertEqual(chat["messages"][2], {"role": "tool", "tool_call_id": "t1", "content": "Error: partial"})
        self.assertEqual(chat["messages"][3]["role"], "user")
        self.assertEqual(chat["messages"][3]["content"][1], {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA=="}})

    def test_runtime_only_tool_result_blocks_are_dropped(self):
        chat = translate_request(
            {"model": "m", "max_tokens": 5, "messages": [
                {"role": "user", "content": "find"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "ToolSearch", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
                    {"type": "text", "text": "found"},
                    {"type": "tool_reference", "tool_name": "Read"},
                ]}]},
            ]},
            MESSAGES,
            CHAT,
        )
        self.assertEqual(chat["messages"][2], {"role": "tool", "tool_call_id": "t1", "content": "found"})

    def test_server_tools_and_stateful_features_are_rejected(self):
        base = {"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}
        for extra, param in [
            ({"tools": [{"type": "web_search_20250305", "name": "web_search"}]}, "tools"),
            ({"tools": [{"type": "bash_20250124", "name": "bash"}]}, "tools"),
            ({"mcp_servers": [{"type": "url", "url": "https://mcp.example"}]}, "mcp_servers"),
            ({"container": "container_1"}, "container"),
        ]:
            with self.subTest(param=param), self.assertRaises(TranslationError) as raised:
                translate_request({**base, **extra}, MESSAGES, CHAT)
            self.assertEqual(raised.exception.param, param)

    def test_history_from_server_tools_is_dropped_safely(self):
        chat = translate_request(
            {"model": "m", "max_tokens": 5, "messages": [
                {"role": "user", "content": "search"},
                {"role": "assistant", "content": [
                    {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {"query": "x"}},
                    {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1", "content": []},
                    {"type": "text", "text": "Found it."},
                ]},
                {"role": "user", "content": "ok"},
            ]},
            MESSAGES,
            CHAT,
        )
        self.assertEqual(chat["messages"][1], {"role": "assistant", "content": "Found it."})


class ChatToMessagesRequestTest(unittest.TestCase):
    def test_golden_request(self):
        body = translate_request(
            {
                "model": "minimax-m3",
                "messages": [
                    {"role": "system", "content": "Rules."},
                    {"role": "developer", "content": [{"type": "text", "text": "More rules."}]},
                    {"role": "user", "content": [
                        {"type": "text", "text": "Look"},
                        {"type": "image_url", "image_url": {"url": "data:image/webp;base64,UklG", "detail": "high"}},
                    ]},
                    {"role": "assistant", "content": None, "tool_calls": [
                        {"id": "functions.lookup:0", "type": "function", "function": {"name": "lookup", "arguments": "{\"q\":1}"}},
                        {"id": "call_2", "type": "function", "function": {"name": "lookup", "arguments": "not json"}},
                    ]},
                    {"role": "tool", "tool_call_id": "functions.lookup:0", "content": "one"},
                    {"role": "tool", "tool_call_id": "call_2", "content": [{"type": "text", "text": "two"}]},
                    {"role": "user", "content": "Summarize"},
                ],
                "tools": [{"type": "function", "function": {"name": "lookup", "description": "Find", "parameters": {"properties": {"q": {"type": "integer"}}}}}],
                "tool_choice": "required",
                "parallel_tool_calls": False,
                "max_completion_tokens": 300,
                "temperature": 1.6,
                "top_p": 0.9,
                "stop": "STOP",
                "user": "user-1",
                "response_format": {"type": "json_schema", "json_schema": {"name": "out", "schema": {"type": "object"}}},
                "stream": True,
            },
            CHAT,
            MESSAGES,
        )
        self.assertEqual(
            body,
            {
                "model": "minimax-m3",
                "messages": [
                    {"role": "user", "content": [
                        {"type": "text", "text": "Look"},
                        {"type": "image", "source": {"type": "base64", "media_type": "image/webp", "data": "UklG"}},
                    ]},
                    {"role": "assistant", "content": [
                        {"type": "tool_use", "id": "functions_lookup_0", "name": "lookup", "input": {"q": 1}},
                        {"type": "tool_use", "id": "call_2", "name": "lookup", "input": {"_raw_arguments": "not json"}},
                    ]},
                    {"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": "functions_lookup_0", "content": "one"},
                        {"type": "tool_result", "tool_use_id": "call_2", "content": [{"type": "text", "text": "two"}]},
                        {"type": "text", "text": "Summarize"},
                    ]},
                ],
                "max_tokens": 300,
                "system": "Rules.\n\nMore rules.",
                "temperature": 1.0,
                "top_p": 0.9,
                "stop_sequences": ["STOP"],
                "stream": True,
                "metadata": {"user_id": "user-1"},
                "tools": [{"name": "lookup", "input_schema": {"properties": {"q": {"type": "integer"}}, "type": "object"}, "description": "Find"}],
                "tool_choice": {"type": "any", "disable_parallel_tool_use": True},
                "output_config": {"format": {"type": "json_schema", "schema": {"type": "object"}}},
            },
        )

    def test_reasoning_effort_becomes_a_bounded_thinking_budget(self):
        base = {"model": "m", "messages": [{"role": "user", "content": "hi"}], "temperature": 0.3, "top_p": 0.5}
        high = translate_request({**base, "reasoning_effort": "high"}, CHAT, MESSAGES)
        self.assertEqual(high["max_tokens"], 8192)
        self.assertEqual(high["thinking"], {"type": "enabled", "budget_tokens": 8191})
        self.assertNotIn("temperature", high)
        self.assertNotIn("top_p", high)
        tiny = translate_request({**base, "reasoning_effort": "low", "max_tokens": 500}, CHAT, MESSAGES)
        self.assertNotIn("thinking", tiny, "a budget under 1024 tokens cannot be honoured")
        self.assertEqual(tiny["temperature"], 0.3)
        off = translate_request({**base, "reasoning_effort": "none"}, CHAT, MESSAGES)
        self.assertEqual(off["thinking"], {"type": "disabled"})

    def test_json_object_adds_a_system_instruction(self):
        body = translate_request({"model": "m", "messages": [{"role": "user", "content": "hi"}], "response_format": {"type": "json_object"}}, CHAT, MESSAGES)
        self.assertIn("valid JSON object", body["system"])

    def test_untranslatable_chat_features_are_rejected(self):
        base = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        for extra, param in [
            ({"n": 2}, "n"),
            ({"modalities": ["text", "audio"]}, "modalities"),
            ({"functions": [{"name": "f"}]}, "functions"),
            ({"messages": [{"role": "user", "content": [{"type": "input_audio", "input_audio": {"data": "x", "format": "wav"}}]}]}, "messages"),
            ({"tools": [{"type": "custom", "custom": {"name": "patch"}}]}, "tools"),
        ]:
            with self.subTest(param=param), self.assertRaises(TranslationError) as raised:
                translate_request({**base, **extra}, CHAT, MESSAGES)
            self.assertEqual(raised.exception.param, param)


class ResponsesRequestTest(unittest.TestCase):
    def test_golden_responses_to_chat(self):
        chat = translate_request(
            {
                "model": "auto:glm-5.2",
                "instructions": "Be brief",
                "input": [
                    {"role": "developer", "content": "Style guide"},
                    {"type": "message", "role": "user", "content": [
                        {"type": "input_text", "text": "Read"},
                        {"type": "input_image", "image_url": "https://img.example/b.png", "detail": "low"},
                    ]},
                    {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "thinking"}]},
                    {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Calling."}]},
                    {"type": "function_call", "call_id": "call_1", "name": "read", "arguments": "{}"},
                    {"type": "function_call_output", "call_id": "call_1", "output": "file text"},
                ],
                "tools": [{"type": "function", "name": "read", "parameters": {"type": "object"}, "strict": False}],
                "tool_choice": {"type": "function", "name": "read"},
                "parallel_tool_calls": False,
                "max_output_tokens": 64,
                "temperature": 0.5,
                "text": {"format": {"type": "json_schema", "name": "answer", "schema": {"type": "object"}, "strict": True}},
                "reasoning": {"effort": "low", "summary": "auto"},
                "store": True,
                "include": ["reasoning.encrypted_content"],
                "stream": True,
            },
            RESPONSES,
            CHAT,
        )
        self.assertEqual(
            chat,
            {
                "model": "auto:glm-5.2",
                "messages": [
                    {"role": "system", "content": "Be brief"},
                    {"role": "system", "content": "Style guide"},
                    {"role": "user", "content": [
                        {"type": "text", "text": "Read"},
                        {"type": "image_url", "image_url": {"url": "https://img.example/b.png", "detail": "low"}},
                    ]},
                    {"role": "assistant", "content": "Calling.", "tool_calls": [
                        {"id": "call_1", "type": "function", "function": {"name": "read", "arguments": "{}"}},
                    ], "reasoning_content": "thinking"},
                    {"role": "tool", "tool_call_id": "call_1", "content": "file text"},
                ],
                "max_tokens": 64,
                "temperature": 0.5,
                "stream": True,
                "stream_options": {"include_usage": True},
                "tools": [{"type": "function", "function": {"name": "read", "parameters": {"type": "object"}, "strict": False}}],
                "tool_choice": {"type": "function", "function": {"name": "read"}},
                "parallel_tool_calls": False,
                "response_format": {"type": "json_schema", "json_schema": {"name": "answer", "schema": {"type": "object"}, "strict": True}},
                "reasoning_effort": "low",
            },
        )

    def test_reasoning_items_attach_to_tool_turns(self):
        chat = translate_request(
            {"model": "m", "input": [
                {"role": "user", "content": "go"},
                {"type": "reasoning", "content": [{"type": "reasoning_text", "text": "because"}]},
                {"type": "function_call", "call_id": "c", "name": "f", "arguments": "{}"},
            ]},
            RESPONSES,
            CHAT,
        )
        self.assertEqual(chat["messages"][1]["reasoning_content"], "because")

    def test_allowed_tools_filters_the_tool_list(self):
        chat = translate_request(
            {"model": "m", "input": "hi", "tools": [
                {"type": "function", "name": "a", "parameters": {}},
                {"type": "function", "name": "b", "parameters": {}},
            ], "tool_choice": {"type": "allowed_tools", "mode": "required", "tools": [{"type": "function", "name": "b"}]}},
            RESPONSES,
            CHAT,
        )
        self.assertEqual([tool["function"]["name"] for tool in chat["tools"]], ["b"])
        self.assertEqual(chat["tool_choice"], "required")

    def test_stateful_and_built_in_features_are_rejected(self):
        for extra, param in [
            ({"previous_response_id": "resp_1"}, "previous_response_id"),
            ({"conversation": "conv_1"}, "conversation"),
            ({"background": True}, "background"),
            ({"prompt": {"id": "pmpt_1"}}, "prompt"),
            ({"tools": [{"type": "web_search"}]}, "tools"),
            ({"tools": [{"type": "file_search", "vector_store_ids": ["vs"]}]}, "tools"),
            ({"tool_choice": {"type": "web_search_preview"}}, "tool_choice"),
            ({"input": [{"type": "item_reference", "id": "msg_1"}]}, "input"),
            ({"input": [{"type": "web_search_call", "id": "ws_1"}]}, "input"),
        ]:
            with self.subTest(param=param, extra=extra), self.assertRaises(TranslationError) as raised:
                translate_request({"model": "m", "input": "hi", **extra}, RESPONSES, CHAT)
            self.assertEqual(raised.exception.param, param)

    def test_golden_chat_to_responses(self):
        body = translate_request(
            {
                "model": "grok-4.6",
                "messages": [
                    {"role": "system", "content": "Rules"},
                    {"role": "user", "content": [
                        {"type": "text", "text": "See"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA=="}},
                    ]},
                    {"role": "assistant", "content": "Let me look.", "tool_calls": [
                        {"id": "call_9", "type": "function", "function": {"name": "zoom", "arguments": "{\"x\":1}"}},
                    ]},
                    {"role": "tool", "tool_call_id": "call_9", "content": "zoomed"},
                ],
                "tools": [{"type": "function", "function": {"name": "zoom", "parameters": {"type": "object"}}}],
                "tool_choice": "auto",
                "max_tokens": 200,
                "stop": ["X"],
                "reasoning_effort": "high",
                "response_format": {"type": "json_object"},
                "stream": True,
            },
            CHAT,
            RESPONSES,
        )
        self.assertEqual(
            body,
            {
                "model": "grok-4.6",
                "input": [
                    {"role": "system", "content": "Rules"},
                    {"role": "user", "content": [
                        {"type": "input_text", "text": "See"},
                        {"type": "input_image", "image_url": "data:image/png;base64,AA==", "detail": "auto"},
                    ]},
                    {"role": "assistant", "content": "Let me look."},
                    {"type": "function_call", "call_id": "call_9", "name": "zoom", "arguments": "{\"x\":1}"},
                    {"type": "function_call_output", "call_id": "call_9", "output": "zoomed"},
                ],
                "store": False,
                "max_output_tokens": 200,
                "stream": True,
                "tools": [{"type": "function", "name": "zoom", "parameters": {"type": "object"}, "strict": False}],
                "tool_choice": "auto",
                "text": {"format": {"type": "json_object"}},
                "reasoning": {"effort": "high"},
            },
        )

    def test_responses_to_messages_composes_through_chat(self):
        body = translate_request(
            {"model": "m", "instructions": "Sys", "input": "hi", "max_output_tokens": 50}, RESPONSES, MESSAGES
        )
        self.assertEqual(
            body,
            {"model": "m", "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}], "max_tokens": 50, "system": "Sys"},
        )


class NonStreamingResponseTest(unittest.TestCase):
    MESSAGE = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "minimax-m3",
        "content": [
            {"type": "thinking", "thinking": "Hmm.", "signature": "s"},
            {"type": "text", "text": "Paris."},
            {"type": "tool_use", "id": "toolu_2", "name": "save", "input": {"city": "Paris"}},
        ],
        "stop_reason": "tool_use",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "cache_creation_input_tokens": 4, "cache_read_input_tokens": 6, "output_tokens": 9},
    }
    COMPLETION = {
        "id": "abc",
        "object": "chat.completion",
        "created": 7,
        "model": "kimi-k2.6",
        "choices": [{"index": 0, "finish_reason": "length", "message": {
            "role": "assistant",
            "content": "Partial",
            "reasoning_content": "why",
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "f", "arguments": "{\"a\":1}"}}],
        }}],
        "usage": {"prompt_tokens": 30, "completion_tokens": 5, "total_tokens": 35, "prompt_tokens_details": {"cached_tokens": 10}, "completion_tokens_details": {"reasoning_tokens": 2}},
    }

    def test_messages_to_chat(self):
        chat = translate_response(self.MESSAGE, MESSAGES, CHAT, model="opencode:minimax-m3")
        self.assertEqual(chat["model"], "opencode:minimax-m3")
        self.assertEqual(chat["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(
            chat["choices"][0]["message"],
            {
                "role": "assistant",
                "content": "Paris.",
                "tool_calls": [{"id": "toolu_2", "type": "function", "function": {"name": "save", "arguments": "{\"city\":\"Paris\"}"}}],
                "reasoning_content": "Hmm.",
            },
        )
        self.assertEqual(
            chat["usage"],
            {"prompt_tokens": 20, "completion_tokens": 9, "total_tokens": 29, "prompt_tokens_details": {"cached_tokens": 6, "cache_write_tokens": 4}},
        )

    def test_chat_to_messages(self):
        message = translate_response(self.COMPLETION, CHAT, MESSAGES, model="auto:x")
        self.assertEqual(message["id"], "msg_abc")
        self.assertEqual(message["model"], "auto:x")
        self.assertEqual(message["stop_reason"], "max_tokens")
        self.assertEqual(
            message["content"],
            [
                {"type": "thinking", "thinking": "why", "signature": ""},
                {"type": "text", "text": "Partial"},
                {"type": "tool_use", "id": "call_1", "name": "f", "input": {"a": 1}},
            ],
        )
        self.assertEqual(
            message["usage"],
            {"input_tokens": 20, "output_tokens": 5, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 10},
        )

    def test_messages_round_trip_preserves_cache_accounting(self):
        chat = translate_response(self.MESSAGE, MESSAGES, CHAT)
        back = translate_response(chat, CHAT, MESSAGES)
        self.assertEqual(back["usage"], {**self.MESSAGE["usage"]})

    def test_chat_to_responses(self):
        response = translate_response(self.COMPLETION, CHAT, RESPONSES, model="auto:x", request={"tools": [{"type": "function", "name": "f"}], "max_output_tokens": 5})
        self.assertEqual(response["status"], "incomplete")
        self.assertEqual(response["incomplete_details"], {"reason": "max_output_tokens"})
        self.assertEqual([item["type"] for item in response["output"]], ["reasoning", "message", "function_call"])
        self.assertEqual(response["output"][0]["content"], [{"type": "reasoning_text", "text": "why"}])
        self.assertEqual(response["output"][2]["call_id"], "call_1")
        self.assertEqual(response["output_text"], "Partial")
        self.assertEqual(response["tools"], [{"type": "function", "name": "f"}])
        self.assertEqual(
            response["usage"],
            {"input_tokens": 30, "input_tokens_details": {"cached_tokens": 10}, "output_tokens": 5, "output_tokens_details": {"reasoning_tokens": 2}, "total_tokens": 35},
        )

    def test_responses_to_chat(self):
        chat = translate_response(
            {
                "id": "resp_1",
                "object": "response",
                "status": "incomplete",
                "incomplete_details": {"reason": "content_filter"},
                "model": "grok-4.6",
                "output": [
                    {"type": "reasoning", "id": "rs", "summary": [{"type": "summary_text", "text": "s1"}, {"type": "summary_text", "text": "s2"}]},
                    {"type": "message", "id": "m", "role": "assistant", "content": [{"type": "output_text", "text": "Hi"}]},
                    {"type": "function_call", "id": "fc", "call_id": "call_3", "name": "g", "arguments": "{}"},
                    {"type": "web_search_call", "id": "ws"},
                ],
                "usage": {"input_tokens": 3, "output_tokens": 4, "input_tokens_details": {"cached_tokens": 1}, "output_tokens_details": {"reasoning_tokens": 2}},
            },
            RESPONSES,
            CHAT,
        )
        self.assertEqual(chat["choices"][0]["finish_reason"], "content_filter")
        self.assertEqual(chat["choices"][0]["message"]["reasoning_content"], "s1\n\ns2")
        self.assertEqual(chat["choices"][0]["message"]["tool_calls"][0]["id"], "call_3")
        self.assertEqual(chat["usage"]["completion_tokens_details"], {"reasoning_tokens": 2})

    def test_failed_response_is_an_upstream_failure(self):
        with self.assertRaises(UpstreamFailure) as raised:
            translate_response(
                {"object": "response", "status": "failed", "error": {"code": "server_error", "message": "boom"}},
                RESPONSES,
                CHAT,
            )
        self.assertEqual(raised.exception.message, "boom")

    def test_chat_without_choices_stays_readable(self):
        response = translate_response({"id": "resp_native", "object": "response", "output": []}, CHAT, RESPONSES)
        self.assertEqual(response["output_text"], "")


class StreamTranslationTest(unittest.TestCase):
    def test_messages_stream_to_chat_golden(self):
        frames = parse_frames("".join(translate_stream(ANTHROPIC_TOOL_STREAM, MESSAGES, CHAT, model="auto:claude")))
        deltas = [data["choices"][0]["delta"] for _, data, _ in frames if isinstance(data, dict) and data.get("choices")]
        self.assertEqual(
            deltas,
            [
                {"role": "assistant", "content": ""},
                {"reasoning_content": "Plan."},
                {"content": "Checking"},
                {"tool_calls": [{"index": 0, "id": "toolu_7", "type": "function", "function": {"name": "get_weather", "arguments": ""}}]},
                {"tool_calls": [{"index": 0, "function": {"arguments": "{\"city\":"}}]},
                {"tool_calls": [{"index": 0, "function": {"arguments": " \"Paris\"}"}}]},
                {},
            ],
        )
        final = [data for _, data, _ in frames if isinstance(data, dict) and data.get("usage")][0]
        self.assertEqual(final["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(final["usage"]["prompt_tokens"], 25)
        self.assertEqual(final["usage"]["completion_tokens"], 30)
        self.assertEqual(final["model"], "auto:claude")
        self.assertIn((None, None, "ping"), frames, "Anthropic pings become SSE comments")
        self.assertEqual(frames[-1], (None, "[DONE]", None))

    def test_chat_stream_to_messages_golden(self):
        frames = parse_frames("".join(translate_stream(CHAT_TOOL_STREAM, CHAT, MESSAGES, model="opencode:kimi-k2.6")))
        events = [(event, data) for event, data, _ in frames]
        names = [event for event, _ in events]
        self.assertEqual(
            names,
            [
                "message_start",
                "content_block_start", "content_block_delta", "content_block_stop",
                "content_block_start", "content_block_delta", "content_block_delta", "content_block_stop",
                "content_block_start", "content_block_delta", "content_block_stop",
                "message_delta", "message_stop",
            ],
        )
        self.assertEqual(events[0][1]["message"]["model"], "opencode:kimi-k2.6")
        self.assertEqual(events[1][1]["content_block"], {"type": "thinking", "thinking": "", "signature": ""})
        self.assertEqual(events[2][1]["delta"], {"type": "thinking_delta", "thinking": "Think"})
        self.assertEqual(events[8][1], {"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use", "id": "functions_get_weather_0", "name": "get_weather", "input": {}}})
        self.assertEqual(events[9][1]["delta"], {"type": "input_json_delta", "partial_json": "{\"city\":\"Paris\"}"})
        self.assertEqual(
            events[11][1],
            {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
             "usage": {"input_tokens": 10, "output_tokens": 8, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 2}},
        )

    def test_chat_stream_to_responses_golden(self):
        frames = parse_frames("".join(translate_stream(CHAT_TOOL_STREAM, CHAT, RESPONSES, model="auto:glm-5.2")))
        names = [event for event, _, _ in frames]
        self.assertEqual(
            names,
            [
                "response.created", "response.in_progress",
                "response.output_item.added", "response.content_part.added", "response.reasoning_text.delta",
                "response.reasoning_text.done", "response.content_part.done", "response.output_item.done",
                "response.output_item.added", "response.content_part.added",
                "response.output_text.delta", "response.output_text.delta",
                "response.output_text.done", "response.content_part.done", "response.output_item.done",
                "response.output_item.added", "response.function_call_arguments.delta",
                "response.function_call_arguments.done", "response.output_item.done",
                "response.completed",
            ],
        )
        payloads = [data for _, data, _ in frames]
        self.assertEqual([payload["sequence_number"] for payload in payloads], list(range(len(payloads))))
        completed = payloads[-1]["response"]
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["model"], "auto:glm-5.2")
        self.assertEqual(completed["output"][1]["content"][0]["text"], "Hi there")
        self.assertEqual(completed["output"][2]["arguments"], "{\"city\":\"Paris\"}")
        self.assertEqual(completed["output"][2]["call_id"], "functions.get_weather:0")
        self.assertEqual(completed["usage"]["input_tokens_details"], {"cached_tokens": 2})

    def test_responses_stream_to_chat_golden(self):
        stream = sse(
            ("response.created", {"type": "response.created", "sequence_number": 0, "response": {"id": "resp_9", "model": "grok-4.6", "status": "in_progress", "output": []}}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": {"id": "rs_1", "type": "reasoning", "summary": []}}),
            ("response.reasoning_summary_text.delta", {"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "summary_index": 0, "delta": "Plan"}),
            ("response.reasoning_summary_part.added", {"type": "response.reasoning_summary_part.added", "item_id": "rs_1", "summary_index": 1}),
            ("response.reasoning_summary_text.delta", {"type": "response.reasoning_summary_text.delta", "item_id": "rs_1", "summary_index": 1, "delta": "More"}),
            ("response.output_text.delta", {"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 1, "content_index": 0, "delta": "Yo"}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 2, "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "f", "arguments": ""}}),
            ("response.function_call_arguments.delta", {"type": "response.function_call_arguments.delta", "item_id": "fc_1", "output_index": 2, "delta": "{}"}),
            ("response.function_call_arguments.done", {"type": "response.function_call_arguments.done", "item_id": "fc_1", "output_index": 2, "arguments": "{}"}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 3, "item": {"id": "fc_2", "type": "function_call", "call_id": "call_2", "name": "g", "arguments": ""}}),
            ("response.output_item.done", {"type": "response.output_item.done", "output_index": 3, "item": {"id": "fc_2", "type": "function_call", "call_id": "call_2", "name": "g", "arguments": "{\"b\":2}"}}),
            ("response.completed", {"type": "response.completed", "response": {"id": "resp_9", "status": "completed", "usage": {"input_tokens": 5, "output_tokens": 6}}}),
        )
        frames = parse_frames("".join(translate_stream(stream, RESPONSES, CHAT)))
        deltas = [data["choices"][0]["delta"] for _, data, _ in frames if isinstance(data, dict)]
        self.assertEqual(
            deltas,
            [
                {"role": "assistant", "content": ""},
                {"reasoning_content": "Plan"},
                {"reasoning_content": "\n\n"},
                {"reasoning_content": "More"},
                {"content": "Yo"},
                {"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "f", "arguments": ""}}]},
                {"tool_calls": [{"index": 0, "function": {"arguments": "{}"}}]},
                {"tool_calls": [{"index": 1, "id": "call_2", "type": "function", "function": {"name": "g", "arguments": ""}}]},
                {"tool_calls": [{"index": 1, "function": {"arguments": "{\"b\":2}"}}]},
                {},
            ],
        )
        self.assertEqual(frames[-2][1]["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(frames[-2][1]["usage"]["total_tokens"], 11)
        self.assertEqual(frames[-1][1], "[DONE]")

    def test_messages_stream_to_responses_composes_through_chat(self):
        frames = parse_frames("".join(translate_stream(ANTHROPIC_TOOL_STREAM, MESSAGES, RESPONSES)))
        completed = frames[-1][1]["response"]
        self.assertEqual([item["type"] for item in completed["output"]], ["reasoning", "message", "function_call"])
        self.assertEqual(completed["output"][2]["arguments"], "{\"city\": \"Paris\"}")

    def test_tool_name_arriving_late_delays_the_block(self):
        stream = chat_sse(
            chunk({"tool_calls": [{"index": 0, "id": "call_x", "function": {"arguments": "{\"a\""}}]}),
            chunk({"tool_calls": [{"index": 0, "function": {"name": "late", "arguments": ":1}"}}]}),
            chunk(finish="tool_calls"),
        )
        frames = parse_frames("".join(translate_stream(stream, CHAT, MESSAGES)))
        start = [data for event, data, _ in frames if event == "content_block_start"][0]
        self.assertEqual(start["content_block"]["name"], "late")
        partials = [data["delta"]["partial_json"] for event, data, _ in frames if event == "content_block_delta"]
        self.assertEqual("".join(partials), "{\"a\":1}")

    def test_provider_keepalive_comments_are_forwarded(self):
        stream = [b": OPENROUTER PROCESSING\n\n", *chat_sse(chunk({"content": "x"}), chunk(finish="stop"))]
        for target in (MESSAGES, RESPONSES):
            with self.subTest(target=target):
                text = "".join(translate_stream(stream, CHAT, target))
                self.assertIn(": OPENROUTER PROCESSING\n\n", text)


class EarlyEndAndErrorStreamTest(unittest.TestCase):
    TRUNCATED_ANTHROPIC = ANTHROPIC_TOOL_STREAM[:8]
    TRUNCATED_CHAT = chat_sse(chunk({"role": "assistant", "content": ""}), chunk({"content": "Hal"}), done=False)

    def test_early_end_marks_each_target_incomplete(self):
        chat = parse_frames("".join(translate_stream(self.TRUNCATED_ANTHROPIC, MESSAGES, CHAT)))
        self.assertEqual(chat[-2][1]["error"]["code"], "stream_interrupted")
        self.assertEqual(chat[-1][1], "[DONE]")
        self.assertFalse(any(isinstance(d, dict) and d.get("choices") and d["choices"][0]["finish_reason"] for _, d, _ in chat))

        messages = parse_frames("".join(translate_stream(self.TRUNCATED_CHAT, CHAT, MESSAGES)))
        self.assertEqual(messages[-1][0], "error")
        self.assertEqual(messages[-1][1]["error"]["type"], "api_error")
        self.assertNotIn("message_stop", [event for event, _, _ in messages])

        responses = parse_frames("".join(translate_stream(self.TRUNCATED_CHAT, CHAT, RESPONSES)))
        self.assertEqual(responses[-1][0], "response.incomplete")
        final = responses[-1][1]["response"]
        self.assertEqual(final["status"], "incomplete")
        self.assertEqual(final["incomplete_details"], {"reason": "upstream_interrupted"})
        self.assertEqual(final["output"][0]["status"], "incomplete")
        self.assertEqual(final["output"][0]["content"][0]["text"], "Hal")
        self.assertNotIn("response.completed", [event for event, _, _ in responses])

    def test_done_without_finish_reason_is_not_success(self):
        stream = chat_sse(chunk({"content": "cut"}))
        frames = parse_frames("".join(translate_stream(stream, CHAT, MESSAGES)))
        self.assertEqual(frames[-1][0], "error")

    def test_transport_error_mid_stream_ends_with_a_terminal_event(self):
        def broken():
            yield from self.TRUNCATED_CHAT
            raise ConnectionError("reset")

        frames = parse_frames("".join(translate_stream(broken(), CHAT, RESPONSES)))
        self.assertEqual(frames[-1][0], "response.incomplete")

    def test_upstream_error_events_map_to_each_protocol(self):
        anthropic_error = sse(
            ("message_start", {"type": "message_start", "message": {"id": "msg_e", "model": "m", "usage": {}}}),
            ("error", {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}),
        )
        chat = parse_frames("".join(translate_stream(anthropic_error, MESSAGES, CHAT)))
        self.assertEqual(chat[-2][1]["error"], {"message": "Overloaded", "type": "overloaded_error", "code": None})

        chat_error = chat_sse(chunk({"content": "a"}), {"error": {"message": "quota", "type": "rate_limit_error"}}, done=False)
        messages = parse_frames("".join(translate_stream(chat_error, CHAT, MESSAGES)))
        self.assertEqual(messages[-1][1], {"type": "error", "error": {"type": "rate_limit_error", "message": "quota"}})

        responses = parse_frames("".join(translate_stream(chat_error, CHAT, RESPONSES)))
        self.assertEqual([event for event, _, _ in responses[-2:]], ["error", "response.failed"])
        self.assertEqual(responses[-1][1]["response"]["error"], {"code": "rate_limit_error", "message": "quota"})

        failed = sse(
            ("response.created", {"type": "response.created", "response": {"id": "r", "model": "g"}}),
            ("response.failed", {"type": "response.failed", "response": {"status": "failed", "error": {"code": "server_error", "message": "down"}}}),
        )
        chat = parse_frames("".join(translate_stream(failed, RESPONSES, CHAT)))
        self.assertEqual(chat[-2][1]["error"]["message"], "down")

    def test_translation_is_incremental(self):
        consumed = []

        def upstream():
            for index, frame in enumerate(ANTHROPIC_TOOL_STREAM):
                consumed.append(index)
                yield frame

        events = translate_stream(upstream(), MESSAGES, CHAT)
        first = next(events)
        self.assertIn("\"role\":\"assistant\"", first)
        self.assertEqual(consumed, [0], "the first frame is emitted before the rest is read")


class AggregateAndReplayTest(unittest.TestCase):
    def test_aggregate_stream_folds_events(self):
        message = aggregate_stream(CHAT_TOOL_STREAM, CHAT, MESSAGES, model="m")
        self.assertEqual(message["stop_reason"], "tool_use")
        self.assertEqual([block["type"] for block in message["content"]], ["thinking", "text", "tool_use"])
        self.assertEqual(message["content"][2]["input"], {"city": "Paris"})

    def test_aggregate_stream_raises_for_interrupted_streams(self):
        with self.assertRaises(UpstreamFailure):
            aggregate_stream(EarlyEndAndErrorStreamTest.TRUNCATED_CHAT, CHAT, RESPONSES)

    def test_completion_stream_replays_a_json_body(self):
        frames = parse_frames("".join(completion_stream(NonStreamingResponseTest.MESSAGE, MESSAGES, RESPONSES)))
        self.assertEqual(frames[-1][0], "response.completed")
        self.assertEqual(frames[-1][1]["response"]["output"][1]["content"][0]["text"], "Paris.")


class ErrorAndHelperTest(unittest.TestCase):
    def test_errors_cross_the_openai_anthropic_boundary(self):
        self.assertEqual(
            translate_error({"error": {"message": "slow down", "type": "rate_limit_error"}}, 429, CHAT, MESSAGES),
            {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}},
        )
        self.assertEqual(
            translate_error({"type": "error", "error": {"type": "invalid_request_error", "message": "bad"}}, 400, MESSAGES, CHAT),
            {"error": {"message": "bad", "type": "invalid_request_error", "param": None, "code": None}},
        )
        gateway = {"error": "circuit_open", "message": "Provider paused", "request_id": "req_1"}
        self.assertEqual(
            translate_error(gateway, 503, CHAT, MESSAGES),
            {"type": "error", "error": {"type": "overloaded_error", "message": "Provider paused"}, "request_id": "req_1"},
        )
        self.assertIs(translate_error(gateway, 503, CHAT, RESPONSES), gateway, "OpenAI-family errors pass through")
        self.assertEqual(translate_error("<html>", 502, CHAT, MESSAGES)["error"], {"type": "api_error", "message": "<html>"})

    def test_malformed_shapes_fail_cleanly(self):
        for payload, source, target in [
            ({"model": "m", "input": "hi", "tool_choice": {"type": ["x"]}}, RESPONSES, CHAT),
            ({"model": "m", "input": [{"role": {"x": 1}, "content": "hi"}]}, RESPONSES, CHAT),
            ({"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [{"type": {}}]}]}, MESSAGES, CHAT),
            ({"model": "m", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": 7}]}]}, CHAT, MESSAGES),
        ]:
            with self.subTest(payload=payload), self.assertRaises(TranslationError):
                translate_request(payload, source, target)
        with self.assertRaises(UpstreamFailure):
            translate_response({"content": [{"type": "tool_use", "input": object()}]}, MESSAGES, CHAT)

        stream = chat_sse(
            {"choices": [{"index": {"bad": 1}, "delta": {"content": 5, "tool_calls": [{"index": [], "function": "x"}]}, "finish_reason": {}}]},
            chunk({"content": "ok"}),
            chunk(finish="stop"),
        )
        frames = parse_frames("".join(translate_stream(stream, CHAT, MESSAGES)))
        self.assertEqual(frames[-1][0], "message_stop")
        broken = sse(("content_block_start", {"type": "content_block_start", "index": [1], "content_block": {"type": "text"}}))
        frames = parse_frames("".join(translate_stream(broken, MESSAGES, RESPONSES)))
        self.assertEqual(frames[-1][0], "response.failed")

    def test_strip_unsigned_thinking(self):
        payload = {"messages": [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [{"type": "thinking", "thinking": "x", "signature": ""}]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "y", "signature": ""},
                {"type": "thinking", "thinking": "z", "signature": "real"},
                {"type": "text", "text": "a"},
            ]},
        ]}
        cleaned = strip_unsigned_thinking(payload)
        self.assertEqual(len(cleaned["messages"]), 2)
        self.assertEqual(cleaned["messages"][1]["content"][0]["signature"], "real")


if __name__ == "__main__":
    unittest.main()
