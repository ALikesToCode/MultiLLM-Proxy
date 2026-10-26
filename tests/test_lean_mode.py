"""Lean mode: cache, clear, condense and budget Claude API requests without editing history."""

import json
import os
from unittest.mock import patch

import pytest

from services import lean_mode
from services.lean_mode import (
    CONCISE_STYLE,
    CONTEXT_MANAGEMENT_BETA,
    LeanPolicy,
    clip_tool_text,
    condense_shell_output,
    estimate_prompt_tokens,
    lean_policy,
    merge_beta_header,
)
from services.native_token_count import NativeTokenCountError
from tests.test_anthropic_provider import MESSAGE, MODEL, SELECTOR, upstream
from tests.test_protocol_routes import ADMIN, ANTHROPIC_STREAM, sse_upstream
from tests.unified_api_test_case import UnifiedApiTestCase

SHELL_OUTPUT = (
    "\x1b[32mCompiling\x1b[0m crate\n"
    "downloading 10%\rdownloading 55%\rdownloading 100%\n"
    + "warning: unused import\n" * 6
    + "\n\n\n\n"
    + "\x1b]0;title\x07error: failed\n"
)
TOOLS = [{"name": "Bash", "description": "Run a command", "input_schema": {"type": "object"}}]


def tool_turn(call_id, output, name="Bash"):
    return [
        {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": call_id, "name": name, "input": {"command": "cargo build"}}],
        },
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": call_id, "content": output}]},
    ]


def conversation(turns):
    messages = [{"role": "user", "content": "Build the project"}]
    for index in range(turns):
        messages.extend(tool_turn(f"call_{index}", SHELL_OUTPUT))
    return {"model": MODEL, "max_tokens": 4096, "system": "You are a coding agent.", "tools": TOOLS, "messages": messages}


class LeanContext:
    """Run prepare_lean_request inside a lean request context."""

    def __init__(self, app):
        self.app = app

    def prepare(self, body, headers=None):
        with self.app.test_request_context("/v1/messages", headers=headers or {}):
            from flask import request

            request.environ[lean_mode.LEAN_ENVIRON_KEY] = True
            return lean_mode.prepare_lean_request(
                body,
                provider="anthropic",
                endpoint="v1/messages",
                request_headers=headers or {},
                base_urls={"anthropic": "https://api.anthropic.com"},
            )


@pytest.fixture
def lean():
    from flask import Flask

    return LeanContext(Flask(__name__))


def test_shell_output_is_condensed_deterministically_and_idempotently():
    condensed = condense_shell_output(SHELL_OUTPUT)
    assert condensed == (
        "Compiling crate\n"
        "downloading 100%\n"
        "warning: unused import\n"
        "[previous line repeated 5 more times]\n"
        "\n"
        "error: failed\n"
    )
    assert condense_shell_output(condensed) == condensed
    assert condense_shell_output("ok\n\nok\n") == "ok\n\nok\n"


def test_oversized_tool_text_keeps_head_and_tail():
    text = "h" * 60 + "m" * 100 + "t" * 40
    clipped = clip_tool_text(text, 100)
    assert clipped.startswith("h" * 50)
    assert clipped.endswith("m" * 10 + "t" * 40)
    assert "[MultiLLM lean: 100 characters omitted from the middle of this tool result]" in clipped
    assert clip_tool_text(text, 0) == text
    assert clip_tool_text(text, 500) == text


def test_policy_reads_environment_with_safe_defaults():
    assert lean_policy({}) == LeanPolicy()
    policy = lean_policy(
        {
            "LEAN_PROMPT_TOKEN_LIMIT": "90000",
            "LEAN_CLEAR_TRIGGER_TOKENS": "0",
            "LEAN_CLEAR_EXCLUDE_TOOLS": "Read, Grep",
            "LEAN_CACHE_TTL": "1h",
            "LEAN_CONDENSE_SHELL_OUTPUT": "false",
            "LEAN_TOOL_RESULT_MAX_CHARS": "bad",
            "LEAN_STYLE": "caveman",
        }
    )
    assert policy.prompt_token_limit == 90_000
    assert policy.clear_trigger_tokens == 0
    assert policy.clear_exclude_tools == ("Read", "Grep")
    assert policy.cache_ttl == "1h"
    assert policy.condense_shell_output is False
    assert policy.tool_result_max_chars == lean_mode.DEFAULT_TOOL_RESULT_MAX_CHARS
    assert policy.style == "concise"


def test_prepared_body_caches_clears_and_condenses_only_shell_results(lean):
    body = conversation(1)
    body["messages"].extend(tool_turn("read_1", "\x1b[1mexact file bytes\x1b[0m  \n", name="Read"))
    decision = lean.prepare(body)
    prepared = decision.body
    assert decision.active
    assert decision.betas == (CONTEXT_MANAGEMENT_BETA,)
    assert decision.stages == ("cache", "clear-tool-uses", "condense-shell")
    assert prepared["cache_control"] == {"type": "ephemeral"}
    assert prepared["system"] == [
        {"type": "text", "text": "You are a coding agent.", "cache_control": {"type": "ephemeral"}}
    ]
    assert prepared["context_management"] == {
        "edits": [
            {
                "type": "clear_tool_uses_20250919",
                "trigger": {"type": "input_tokens", "value": 80_000},
                "keep": {"type": "tool_uses", "value": 3},
                "clear_at_least": {"type": "input_tokens", "value": 20_000},
            }
        ]
    }
    shell_result = prepared["messages"][2]["content"][0]["content"]
    assert shell_result == condense_shell_output(SHELL_OUTPUT)
    # A file read keeps its exact bytes, escapes and trailing spaces included.
    assert prepared["messages"][4]["content"][0]["content"] == "\x1b[1mexact file bytes\x1b[0m  \n"
    assert decision.condensed_chars > 0
    assert body["messages"][2]["content"][0]["content"] == SHELL_OUTPUT


def test_every_later_turn_repeats_the_earlier_prepared_bytes(lean):
    """Cache hits and preserved thinking both need an unchanged prefix."""
    earlier = lean.prepare(conversation(2)).body
    later = lean.prepare(conversation(3)).body

    def dumped(value):
        return json.dumps(value, sort_keys=False, separators=(",", ":"))

    assert dumped(later["system"]) == dumped(earlier["system"])
    assert dumped(later["tools"]) == dumped(earlier["tools"])
    assert dumped(later["messages"][: len(earlier["messages"])]) == dumped(earlier["messages"])


def test_caller_cache_and_context_management_are_left_alone(lean):
    body = conversation(1)
    body["system"] = [{"type": "text", "text": "Own cache", "cache_control": {"type": "ephemeral"}}]
    body["context_management"] = {"edits": [{"type": "clear_thinking_20251015"}]}
    decision = lean.prepare(body)
    assert "cache_control" not in decision.body
    assert decision.body["system"] == body["system"]
    assert decision.body["context_management"] == body["context_management"]
    assert decision.betas == ()


def test_signed_compaction_blocks_are_not_combined_with_context_editing(lean):
    body = conversation(1)
    body["messages"].insert(0, {"role": "assistant", "content": [{"type": "compaction", "content": "summary"}]})
    assert lean.prepare(body).betas == ()


def test_plain_chat_without_tools_only_gets_caching(lean):
    decision = lean.prepare({"model": MODEL, "max_tokens": 64, "messages": [{"role": "user", "content": "Hi"}]})
    assert decision.stages == ("cache",)
    assert "context_management" not in decision.body
    assert decision.body["cache_control"] == {"type": "ephemeral"}


def test_concise_style_is_opt_in_and_cached_with_the_system_prompt(lean):
    assert "concise-style" not in lean.prepare(conversation(1)).stages
    decision = lean.prepare(conversation(1), headers={"X-MultiLLM-Lean-Style": "caveman"})
    assert "concise-style" in decision.stages
    assert decision.body["system"] == [
        {"type": "text", "text": "You are a coding agent."},
        {"type": "text", "text": CONCISE_STYLE, "cache_control": {"type": "ephemeral"}},
    ]


def test_tools_only_request_caches_its_last_tool(lean):
    body = {"model": MODEL, "max_tokens": 64, "tools": TOOLS, "messages": [{"role": "user", "content": "Hi"}]}
    with patch.dict(os.environ, {"LEAN_CACHE_TTL": "1h"}):
        prepared = lean.prepare(body).body
    marker = {"type": "ephemeral", "ttl": "1h"}
    assert prepared["cache_control"] == marker
    assert prepared["tools"][-1]["cache_control"] == marker


def test_estimate_counts_media_at_a_flat_size():
    image = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "A" * 900_000}}
    body = {"messages": [{"role": "user", "content": [image, {"type": "text", "text": "abc" * 10}]}]}
    # Text, roles and block types are counted; the 900 KB of base64 is not.
    assert estimate_prompt_tokens(body) == len("user" "text" + "abc" * 10) // 3 + lean_mode.MEDIA_BLOCK_TOKENS


def test_beta_header_merge_keeps_caller_betas_once():
    headers = {"anthropic-beta": "claude-code-20250219, context-management-2025-06-27"}
    merge_beta_header(headers, (CONTEXT_MANAGEMENT_BETA,))
    assert headers == {"anthropic-beta": "claude-code-20250219,context-management-2025-06-27"}
    empty = {}
    merge_beta_header(empty, (CONTEXT_MANAGEMENT_BETA,))
    assert empty == {"Anthropic-Beta": CONTEXT_MANAGEMENT_BETA}


def test_near_limit_prompt_is_counted_and_refused_above_the_price_limit(lean):
    body = conversation(1)
    body["messages"][0]["content"] = "x" * 200_000
    with patch.object(lean_mode, "count_claude_prompt_tokens", return_value=100_001) as count:
        with pytest.raises(lean_mode.LeanPromptTooLong) as raised:
            lean.prepare(body, headers={"anthropic-beta": "claude-code-20250219"})
    assert str(raised.value) == "prompt is too long: 100001 tokens > 100000 maximum"
    counted_body, beta_header, _ = count.call_args.args
    assert counted_body["context_management"]["edits"][0]["type"] == "clear_tool_uses_20250919"
    assert beta_header == "claude-code-20250219,context-management-2025-06-27"
    with patch.object(lean_mode, "count_claude_prompt_tokens", return_value=99_000):
        decision = lean.prepare(body)
    assert (decision.prompt_tokens, decision.prompt_count) == (99_000, "provider")


def test_failed_count_lets_the_request_through(lean):
    body = conversation(1)
    body["messages"][0]["content"] = "x" * 200_000
    with patch.object(lean_mode, "count_claude_prompt_tokens", side_effect=NativeTokenCountError("down", 429)):
        decision = lean.prepare(body)
    assert decision.prompt_count == "estimate"


def test_claude_count_sends_context_management_with_the_lean_beta():
    from services import native_token_count

    captured = {}

    class CountResponse:
        status_code = 200

        def iter_content(self, chunk_size):
            yield b'{"input_tokens": 1234}'

        def close(self):
            pass

    def provider_http(provider, method, url, **kwargs):
        captured.update(provider=provider, url=url, **kwargs)
        return CountResponse()

    body = {**conversation(1), "context_management": {"edits": []}, "cache_control": {"type": "ephemeral"}, "stream": True}
    with patch("services.auth_service.AuthService.get_api_key", return_value="claude-key"), patch(
        "services.provider_dispatch.provider_http", provider_http
    ):
        count = native_token_count.count_claude_prompt_tokens(
            body, CONTEXT_MANAGEMENT_BETA, {"anthropic": "https://api.anthropic.com"}
        )
    assert count == 1234
    assert captured["url"] == "https://api.anthropic.com/v1/messages/count_tokens"
    assert captured["headers"]["X-Api-Key"] == "claude-key"
    assert captured["headers"]["Anthropic-Beta"] == CONTEXT_MANAGEMENT_BETA
    assert set(captured["json"]) == {"model", "messages", "system", "tools", "context_management"}


class LeanRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["ANTHROPIC_API_KEY"] = "anthropic-provider-key"

    def post(self, path, body, response=None, headers=None):
        with patch(
            "app.ProxyService.make_request",
            return_value=response if response is not None else upstream(MESSAGE),
        ) as send:
            result = self.client.post(path, json=body, headers=headers or ADMIN)
            result.get_data()
        return result, send

    def test_lean_messages_send_a_cached_cleared_body(self):
        body = {**conversation(1), "model": SELECTOR}
        result, send = self.post(
            "/lean/v1/messages",
            body,
            headers={"X-Api-Key": "admin-test-key", "Anthropic-Beta": "test-beta"},
        )
        self.assertEqual(result.status_code, 200)
        kwargs = send.call_args.kwargs
        self.assertEqual(kwargs["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(kwargs["headers"]["Anthropic-Beta"], f"test-beta,{CONTEXT_MANAGEMENT_BETA}")
        sent = json.loads(kwargs["data"])
        self.assertEqual(sent["cache_control"], {"type": "ephemeral"})
        self.assertIn("context_management", sent)
        self.assertEqual(sent["messages"][2]["content"][0]["content"], condense_shell_output(SHELL_OUTPUT))
        self.assertEqual(result.headers["X-MultiLLM-Lean"], "applied")
        self.assertEqual(result.headers["X-MultiLLM-Lean-Stages"], "cache,clear-tool-uses,condense-shell")
        self.assertEqual(result.headers["X-MultiLLM-Lean-Prompt-Count"], "estimate")
        self.assertEqual(result.get_json()["content"], MESSAGE["content"])

    def test_plain_v1_messages_are_unchanged(self):
        body = {**conversation(1), "model": SELECTOR}
        result, send = self.post("/v1/messages", body, headers={"X-Api-Key": "admin-test-key"})
        self.assertEqual(result.status_code, 200)
        sent = json.loads(send.call_args.kwargs["data"])
        self.assertNotIn("cache_control", sent)
        self.assertNotIn("context_management", sent)
        self.assertEqual(sent["messages"][2]["content"][0]["content"], SHELL_OUTPUT)
        self.assertNotIn("X-MultiLLM-Lean", result.headers)

    def test_lean_chat_translates_then_condenses_shell_tool_output(self):
        result, send = self.post(
            "/lean/v1/chat/completions",
            {
                "model": SELECTOR,
                "tools": [{"type": "function", "function": {"name": "bash", "parameters": {"type": "object"}}}],
                "messages": [
                    {"role": "system", "content": "Be useful"},
                    {"role": "user", "content": "Build"},
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {"id": "call_1", "type": "function", "function": {"name": "bash", "arguments": "{}"}}
                        ],
                    },
                    {"role": "tool", "tool_call_id": "call_1", "content": SHELL_OUTPUT},
                ],
            },
        )
        self.assertEqual(result.status_code, 200)
        sent = json.loads(send.call_args.kwargs["data"])
        self.assertEqual(sent["system"][0]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(sent["messages"][-1]["content"][0]["content"], condense_shell_output(SHELL_OUTPUT))
        self.assertEqual(result.headers["X-MultiLLM-Lean"], "applied")

    def test_lean_responses_stream_is_cached(self):
        result, send = self.post(
            "/lean/v1/responses",
            {"model": SELECTOR, "input": "Hello", "stream": True},
            response=sse_upstream(ANTHROPIC_STREAM),
        )
        self.assertEqual(result.status_code, 200)
        sent = json.loads(send.call_args.kwargs["data"])
        self.assertEqual(sent["cache_control"], {"type": "ephemeral"})
        self.assertEqual(result.headers["X-MultiLLM-Lean-Stages"], "cache")

    def oversized(self):
        return patch.object(lean_mode, "count_claude_prompt_tokens", return_value=150_000)

    def large_input(self):
        return "x" * 200_000

    def test_over_limit_messages_get_anthropic_prompt_too_long(self):
        with self.oversized():
            result, send = self.post(
                "/lean/v1/messages",
                {"model": SELECTOR, "max_tokens": 64, "messages": [{"role": "user", "content": self.large_input()}]},
                headers={"X-Api-Key": "admin-test-key"},
            )
        send.assert_not_called()
        self.assertEqual(result.status_code, 400)
        error = result.get_json()
        self.assertEqual(error["type"], "error")
        self.assertEqual(error["error"]["type"], "invalid_request_error")
        self.assertEqual(error["error"]["message"], "prompt is too long: 150000 tokens > 100000 maximum")
        self.assertEqual(result.headers["X-MultiLLM-Lean-Prompt-Tokens"], "150000")

    def test_over_limit_chat_gets_context_length_exceeded(self):
        with self.oversized():
            result, send = self.post(
                "/lean/v1/chat/completions",
                {"model": SELECTOR, "messages": [{"role": "user", "content": self.large_input()}]},
            )
        send.assert_not_called()
        self.assertEqual(result.status_code, 400)
        error = result.get_json()["error"]
        self.assertEqual(error["code"], "context_length_exceeded")
        self.assertIn("maximum context length is 100000 tokens", error["message"])
        self.assertIn("prompt is too long", error["message"])

    def test_over_limit_responses_stream_fails_like_openai(self):
        with self.oversized():
            result, send = self.post(
                "/lean/v1/responses",
                {"model": SELECTOR, "input": self.large_input(), "stream": True},
            )
        send.assert_not_called()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.mimetype, "text/event-stream")
        frame = result.get_data(as_text=True)
        self.assertTrue(frame.startswith("event: response.failed\ndata: "))
        event = json.loads(frame.split("data: ", 1)[1])
        self.assertEqual(event["response"]["error"]["code"], "context_length_exceeded")

    def test_unknown_lean_path_is_not_routed(self):
        result = self.client.post("/lean/v1/embeddings", json={}, headers=ADMIN)
        # The provider catch-all answers, as it does for any unknown prefix.
        self.assertEqual(result.status_code, 400)
        self.assertIn("Unsupported API provider: lean", result.get_data(as_text=True))


class LeanDisabledRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["LEAN_ENDPOINT_ENABLED"] = "false"
        self.app = self.app_module.create_app()
        self.client = self.app.test_client()

    def test_disabled_lean_prefix_is_not_routed(self):
        result = self.client.post("/lean/v1/messages", json={"model": SELECTOR}, headers=ADMIN)
        self.assertEqual(result.status_code, 400)
        self.assertIn("Unsupported API provider: lean", result.get_data(as_text=True))
