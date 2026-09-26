"""Route tests for Chat <-> Responses <-> Messages bridging on the unified API."""

import io
import json
from unittest.mock import patch

import requests
from flask import Response

from services.auto_route_service import AutoRouteService
from tests.test_protocol_translation import chat_sse, chunk, parse_frames, sse
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"Authorization": "Bearer admin-test-key"}
ANTHROPIC_MESSAGE = {
    "id": "msg_up",
    "type": "message",
    "role": "assistant",
    "model": "minimax-m3",
    "content": [{"type": "text", "text": "Bonjour"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 11, "output_tokens": 3},
}
CHAT_COMPLETION = {
    "id": "chatcmpl-up",
    "object": "chat.completion",
    "created": 1,
    "model": "kimi-k2.6",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello"}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11},
}
RESPONSES_BODY = {
    "id": "resp_up",
    "object": "response",
    "status": "completed",
    "model": "grok-4.6",
    "output": [{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": "Grok says hi", "annotations": []}]}],
    "usage": {"input_tokens": 4, "output_tokens": 3, "total_tokens": 7},
}
CHAT_STREAM = chat_sse(
    chunk({"role": "assistant", "content": ""}, model="kimi-k2.6"),
    chunk({"content": "Hel"}, model="kimi-k2.6"),
    chunk({"content": "lo"}, model="kimi-k2.6"),
    chunk(finish="stop", usage={"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}, model="kimi-k2.6"),
)
ANTHROPIC_STREAM = sse(
    ("message_start", {"type": "message_start", "message": {"id": "msg_s", "model": "minimax-m3", "usage": {"input_tokens": 6}}}),
    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Salut"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
    ("message_stop", {"type": "message_stop"}),
)


def json_upstream(body, status=200):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


def sse_upstream(frames, status=200):
    response = requests.Response()
    response.status_code = status
    response.raw = io.BytesIO(b"".join(frames))
    response.headers["Content-Type"] = "text/event-stream"
    return response


class ProtocolRouteTestCase(UnifiedApiTestCase):
    def post(self, path, body, headers=None, upstream=None):
        side_effect = upstream if isinstance(upstream, list) else None
        return_value = None if side_effect is not None else upstream
        with patch(
            "app.ProxyService.make_request",
            side_effect=side_effect,
            return_value=return_value,
        ) as make_request:
            response = self.client.post(path, headers=headers or ADMIN, json=body)
            # Streamed bodies are generated lazily; read them while the patch is active.
            response.get_data()
        return response, make_request

    def save_route(self, route_id, candidates):
        AutoRouteService.save_route(route_id, candidates, self.app.config["API_BASE_URLS"])


class ChatBridgeRouteTest(ProtocolRouteTestCase):
    def test_chat_reaches_a_messages_only_model(self):
        response, make_request = self.post(
            "/v1/chat/completions",
            {
                "model": "opencode:minimax-m3",
                "messages": [{"role": "system", "content": "Be French"}, {"role": "user", "content": "hi"}],
                "max_tokens": 50,
            },
            upstream=json_upstream(ANTHROPIC_MESSAGE),
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["object"], "chat.completion")
        self.assertEqual(body["choices"][0]["message"]["content"], "Bonjour")
        self.assertEqual(body["choices"][0]["finish_reason"], "stop")
        self.assertEqual(body["usage"], {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14})
        kwargs = make_request.call_args.kwargs
        self.assertEqual(kwargs["url"], "https://opencode.ai/zen/go/v1/messages")
        self.assertEqual(kwargs["headers"]["X-Api-Key"], "opencode-provider-key")
        self.assertEqual(kwargs["headers"]["Anthropic-Version"], "2023-06-01")
        self.assertNotIn("force_raw_passthrough", kwargs)
        self.assertEqual(
            json.loads(kwargs["data"]),
            {
                "model": "minimax-m3",
                "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
                "max_tokens": 50,
                "system": "Be French",
            },
        )

    def test_chat_stream_reaches_a_messages_only_model(self):
        response, make_request = self.post(
            "/v1/chat/completions",
            {"model": "opencode:qwen3.8-max", "messages": [{"role": "user", "content": "hi"}], "stream": True},
            upstream=sse_upstream(ANTHROPIC_STREAM),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/event-stream")
        self.assertEqual(response.headers["X-Accel-Buffering"], "no")
        self.assertTrue(make_request.call_args.kwargs["force_raw_passthrough"])
        frames = parse_frames(response.get_data(as_text=True))
        contents = [d["choices"][0]["delta"].get("content") for _, d, _ in frames if isinstance(d, dict) and d.get("choices")]
        self.assertIn("Salut", contents)
        self.assertEqual(frames[-2][1]["choices"][0]["finish_reason"], "stop")
        self.assertEqual(frames[-1][1], "[DONE]")

    def test_chat_reaches_a_responses_only_model(self):
        response, make_request = self.post(
            "/v1/chat/completions",
            {
                "model": "opencode:grok-4.6",
                "messages": [{"role": "user", "content": "hi"}],
                "tools": [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}],
            },
            upstream=json_upstream(RESPONSES_BODY),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "Grok says hi")
        kwargs = make_request.call_args.kwargs
        self.assertEqual(kwargs["url"], "https://opencode.ai/zen/go/v1/responses")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer opencode-provider-key")
        upstream = json.loads(kwargs["data"])
        self.assertEqual(upstream["input"], [{"role": "user", "content": "hi"}])
        self.assertFalse(upstream["tools"][0]["strict"])
        self.assertFalse(upstream["store"])

    def test_bridge_translates_upstream_errors_and_rejects_untranslatable_requests(self):
        limited = json_upstream({"type": "error", "error": {"type": "rate_limit_error", "message": "Slow down"}}, 429)
        response, _ = self.post(
            "/v1/chat/completions",
            {"model": "opencode:minimax-m3", "messages": [{"role": "user", "content": "hi"}]},
            upstream=limited,
        )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.get_json()["error"]["message"], "Slow down")
        self.assertEqual(response.get_json()["error"]["type"], "rate_limit_error")

        response, make_request = self.post(
            "/v1/chat/completions",
            {"model": "opencode:minimax-m3", "messages": [{"role": "user", "content": "hi"}], "n": 2},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["param"], "n")
        make_request.assert_not_called()

    def test_auto_route_fails_over_into_a_messages_only_candidate(self):
        self.save_route("auto:mixed", ["opencode:kimi-k2.6", "opencode:minimax-m3"])
        refused = json_upstream({"error": {"message": "rate limited"}}, 429)

        response, make_request = self.post(
            "/v1/chat/completions",
            {"model": "auto:mixed", "messages": [{"role": "user", "content": "hi"}]},
            upstream=[refused, json_upstream(ANTHROPIC_MESSAGE)],
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "Bonjour")
        self.assertEqual(
            [call.kwargs["url"] for call in make_request.call_args_list],
            ["https://opencode.ai/zen/go/v1/chat/completions", "https://opencode.ai/zen/go/v1/messages"],
        )
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "opencode:minimax-m3")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")

    def test_optimized_chat_reaches_a_messages_only_model(self):
        response, make_request = self.post(
            "/optimize/v1/chat/completions",
            {"model": "opencode:minimax-m3", "messages": [{"role": "user", "content": "hi"}]},
            upstream=json_upstream(ANTHROPIC_MESSAGE),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "Bonjour")
        self.assertEqual(make_request.call_args.kwargs["url"], "https://opencode.ai/zen/go/v1/messages")


class ResponsesRouteTest(ProtocolRouteTestCase):
    def test_auto_route_is_translated_through_chat_with_route_headers(self):
        self.save_route("auto:chat-test", ["opencode:kimi-k2.6"])
        response, make_request = self.post(
            "/v1/responses",
            {"model": "auto:chat-test", "instructions": "Be brief", "input": "Say hi", "max_output_tokens": 20},
            upstream=json_upstream(CHAT_COMPLETION),
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["object"], "response")
        self.assertEqual(body["model"], "auto:chat-test")
        self.assertEqual(body["output_text"], "Hello")
        self.assertEqual(body["usage"]["input_tokens"], 9)
        self.assertEqual(response.headers["X-MultiLLM-Auto-Route"], "auto:chat-test")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "opencode:kimi-k2.6")
        upstream = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual(upstream["messages"], [{"role": "system", "content": "Be brief"}, {"role": "user", "content": "Say hi"}])
        self.assertEqual(upstream["max_tokens"], 20)
        self.assertEqual(make_request.call_args.kwargs["url"], "https://opencode.ai/zen/go/v1/chat/completions")

    def test_auto_route_keeps_its_failover_rules(self):
        self.save_route("auto:chat-test", ["opencode:kimi-k2.6", "opencode:glm-5.2"])
        refused = json_upstream({"error": {"message": "no balance"}}, 402)
        response, make_request = self.post(
            "/v1/responses",
            {"model": "auto:chat-test", "input": "hi"},
            upstream=[refused, json_upstream(CHAT_COMPLETION)],
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(make_request.call_count, 2)
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "opencode:glm-5.2")

        failed = json_upstream({"error": {"message": "upstream exploded"}}, 500)
        response, make_request = self.post(
            "/v1/responses",
            {"model": "auto:chat-test", "input": "hi"},
            upstream=[failed, json_upstream(CHAT_COMPLETION)],
        )
        self.assertEqual(response.status_code, 200, "a 500 before any output moves on")
        self.assertEqual(make_request.call_count, 2)

        ambiguous = json_upstream({"error": {"message": "upstream timed out"}}, 504)
        response, make_request = self.post(
            "/v1/responses",
            {"model": "auto:chat-test", "input": "hi"},
            upstream=[ambiguous, json_upstream(CHAT_COMPLETION)],
        )
        self.assertEqual(response.status_code, 504, "a possibly billed failure is never replayed")
        self.assertEqual(make_request.call_count, 1)
        self.assertEqual(response.get_json()["error"]["message"], "upstream timed out")

    def test_auto_route_streams_responses_events(self):
        self.save_route("auto:chat-test", ["opencode:kimi-k2.6"])
        response, _ = self.post(
            "/v1/responses",
            {"model": "auto:chat-test", "input": "hi", "stream": True},
            upstream=sse_upstream(CHAT_STREAM),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/event-stream")
        frames = parse_frames(response.get_data(as_text=True))
        self.assertEqual(frames[0][0], "response.created")
        self.assertEqual(frames[-1][0], "response.completed")
        self.assertEqual(frames[-1][1]["response"]["output"][0]["content"][0]["text"], "Hello")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "opencode:kimi-k2.6")

    def test_free_pool_is_translated(self):
        self.app.config.update(FREE_ROUTE_FREE_TIER_PROVIDERS="", FREE_ROUTE_PROVIDER_ORDER="")
        rows = [{"id": "opencode:hy3-free", "provider": "opencode", "model": "hy3-free", "status": "available", "provider_metadata": {}}]
        with (
            patch("services.free_model_policy.build_model_catalog", return_value=rows),
            patch.object(self.app_module.AuthService, "get_api_key", side_effect={"opencode": "free-key"}.get),
        ):
            response, make_request = self.post(
                "/v1/responses", {"model": "free:text", "input": "hi"}, upstream=json_upstream(CHAT_COMPLETION)
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["output_text"], "Hello")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Route"], "free:text")
        self.assertEqual(json.loads(make_request.call_args.kwargs["data"])["messages"], [{"role": "user", "content": "hi"}])

    def test_intelligence_route_is_translated(self):
        with patch(
            "routes.unified.dispatch_intelligence_chat",
            return_value=Response(json.dumps(CHAT_COMPLETION), content_type="application/json"),
        ) as dispatch:
            response = self.client.post(
                "/v1/responses", headers=ADMIN, json={"model": "auto:intelligence", "input": "plan it"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["output_text"], "Hello")
        chat_payload = dispatch.call_args.args[4]
        self.assertEqual(chat_payload["model"], "auto:intelligence")
        self.assertEqual(chat_payload["messages"], [{"role": "user", "content": "plan it"}])

    def test_stateful_and_built_in_features_are_rejected_on_translated_routes(self):
        self.save_route("auto:chat-test", ["opencode:kimi-k2.6"])
        for extra, param in [
            ({"previous_response_id": "resp_123"}, "previous_response_id"),
            ({"tools": [{"type": "web_search"}]}, "tools"),
            ({"tools": [{"type": "file_search", "vector_store_ids": ["vs_1"]}]}, "tools"),
        ]:
            with self.subTest(param=param):
                response, make_request = self.post(
                    "/v1/responses", {"model": "auto:chat-test", "input": "hi", **extra}
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.get_json()["error"]["param"], param)
                self.assertIn(param.split("_")[0], response.get_json()["error"]["message"])
                make_request.assert_not_called()

    def test_explicit_non_native_model_streams_through_the_bridge(self):
        response, make_request = self.post(
            "/v1/responses",
            {"model": "opencode:kimi-k2.6", "input": "hi", "stream": True},
            upstream=sse_upstream(CHAT_STREAM),
        )
        self.assertEqual(response.status_code, 200)
        frames = parse_frames(response.get_data(as_text=True))
        self.assertEqual(frames[-1][0], "response.completed")
        self.assertEqual(frames[-1][1]["response"]["model"], "opencode:kimi-k2.6")
        self.assertTrue(json.loads(make_request.call_args.kwargs["data"])["stream"])

    def test_native_responses_stream_uses_raw_transport_and_is_unchanged(self):
        native = sse(
            ("response.created", {"type": "response.created", "response": {"id": "resp_n"}}),
            ("response.completed", {"type": "response.completed", "response": {"id": "resp_n", "status": "completed"}}),
        )
        response, make_request = self.post(
            "/v1/responses",
            {"model": "opencode:gpt-5.6-luna", "input": "hi", "stream": True},
            upstream=sse_upstream(native),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(), b"".join(native))
        kwargs = make_request.call_args.kwargs
        self.assertEqual(kwargs["url"], "https://opencode.ai/zen/go/v1/responses")
        self.assertTrue(kwargs["force_raw_passthrough"])

    def test_responses_reach_a_messages_only_model(self):
        response, make_request = self.post(
            "/v1/responses",
            {"model": "opencode:minimax-m3", "instructions": "Sys", "input": "hi", "max_output_tokens": 30},
            upstream=json_upstream(ANTHROPIC_MESSAGE),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["output_text"], "Bonjour")
        self.assertEqual(response.get_json()["model"], "opencode:minimax-m3")
        upstream = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual(upstream["system"], "Sys")
        self.assertEqual(upstream["max_tokens"], 30)


class MessagesRouteTest(ProtocolRouteTestCase):
    ANTHROPIC_HEADERS = {
        "x-api-key": "admin-test-key",
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "interleaved-thinking-2025-05-14",
    }
    BODY = {
        "model": "opencode:kimi-k2.6",
        "max_tokens": 64,
        "system": "You are Claude Code.",
        "metadata": {"user_id": "session-1"},
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
    }

    def test_x_api_key_authenticates_and_chat_models_are_translated(self):
        response, make_request = self.post(
            "/v1/messages", self.BODY, headers=self.ANTHROPIC_HEADERS, upstream=json_upstream(CHAT_COMPLETION)
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "id": "msg_chatcmpl-up",
                "type": "message",
                "role": "assistant",
                "model": "opencode:kimi-k2.6",
                "content": [{"type": "text", "text": "Hello"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 9, "output_tokens": 2, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
            },
        )
        kwargs = make_request.call_args.kwargs
        self.assertEqual(kwargs["url"], "https://opencode.ai/zen/go/v1/chat/completions")
        self.assertEqual(
            json.loads(kwargs["data"])["messages"],
            [{"role": "system", "content": "You are Claude Code."}, {"role": "user", "content": "hi"}],
        )
        forwarded = {name.lower() for name in kwargs["headers"]}
        self.assertNotIn("anthropic-version", forwarded)
        self.assertNotIn("anthropic-beta", forwarded)
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer opencode-provider-key")

    def test_bearer_authentication_also_works(self):
        response, _ = self.post("/v1/messages", self.BODY, upstream=json_upstream(CHAT_COMPLETION))
        self.assertEqual(response.status_code, 200)

    def test_authentication_errors_use_the_anthropic_envelope(self):
        for headers in ({}, {"x-api-key": "wrong-key"}):
            with self.subTest(headers=headers):
                response = self.client.post("/v1/messages", headers=headers, json=self.BODY)
                self.assertEqual(response.status_code, 401)
                body = response.get_json()
                self.assertEqual(body["type"], "error")
                self.assertEqual(body["error"]["type"], "authentication_error")
                self.assertTrue(body["error"]["message"])

    def test_streaming_emits_anthropic_events(self):
        response, _ = self.post(
            "/v1/messages",
            {**self.BODY, "stream": True},
            headers=self.ANTHROPIC_HEADERS,
            upstream=sse_upstream(CHAT_STREAM),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/event-stream")
        frames = parse_frames(response.get_data(as_text=True))
        self.assertEqual(
            [event for event, _, _ in frames],
            ["message_start", "content_block_start", "content_block_delta", "content_block_delta",
             "content_block_stop", "message_delta", "message_stop"],
        )
        self.assertEqual(frames[5][1]["usage"]["output_tokens"], 2)

    def test_early_stream_end_emits_an_error_event(self):
        truncated = chat_sse(chunk({"role": "assistant", "content": ""}), chunk({"content": "Hal"}), done=False)
        response, _ = self.post(
            "/v1/messages", {**self.BODY, "stream": True}, headers=self.ANTHROPIC_HEADERS, upstream=sse_upstream(truncated)
        )
        frames = parse_frames(response.get_data(as_text=True))
        self.assertEqual(frames[-1][0], "error")
        self.assertNotIn("message_stop", [event for event, _, _ in frames])

    def test_messages_models_are_passed_through_natively(self):
        body = {
            "model": "opencode:minimax-m3",
            "max_tokens": 64,
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "translated", "signature": ""},
                    {"type": "text", "text": "hello"},
                ]},
                {"role": "user", "content": "again"},
            ],
        }
        native = json_upstream(ANTHROPIC_MESSAGE)
        response, make_request = self.post("/v1/messages", body, headers=self.ANTHROPIC_HEADERS, upstream=native)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), ANTHROPIC_MESSAGE)
        kwargs = make_request.call_args.kwargs
        self.assertEqual(kwargs["url"], "https://opencode.ai/zen/go/v1/messages")
        upstream = json.loads(kwargs["data"])
        self.assertEqual(upstream["model"], "minimax-m3")
        self.assertEqual(upstream["messages"][1]["content"], [{"type": "text", "text": "hello"}])
        self.assertEqual(kwargs["headers"]["Anthropic-Beta"], "interleaved-thinking-2025-05-14")
        self.assertEqual(kwargs["headers"]["X-Api-Key"], "opencode-provider-key")

    def test_auto_route_failover_returns_an_anthropic_message(self):
        self.save_route("auto:claude-code", ["opencode:kimi-k2.6", "opencode:glm-5.2"])
        refused = json_upstream({"error": {"message": "rate limited"}}, 429)
        response, make_request = self.post(
            "/v1/messages",
            {**self.BODY, "model": "auto:claude-code"},
            headers=self.ANTHROPIC_HEADERS,
            upstream=[refused, json_upstream(CHAT_COMPLETION)],
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["type"], "message")
        self.assertEqual(response.get_json()["model"], "auto:claude-code")
        self.assertEqual(make_request.call_count, 2)
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "opencode:glm-5.2")

    def test_upstream_and_validation_errors_use_the_anthropic_envelope(self):
        response, _ = self.post(
            "/v1/messages",
            self.BODY,
            headers=self.ANTHROPIC_HEADERS,
            upstream=json_upstream({"error": {"message": "rate limited", "type": "rate_limit_error"}}, 429),
        )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.get_json(), {"type": "error", "error": {"type": "rate_limit_error", "message": "rate limited"}})

        response, make_request = self.post(
            "/v1/messages",
            {**self.BODY, "tools": [{"type": "web_search_20250305", "name": "web_search"}]},
            headers=self.ANTHROPIC_HEADERS,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["type"], "error")
        self.assertEqual(response.get_json()["error"]["type"], "invalid_request_error")
        self.assertIn("web_search_20250305", response.get_json()["error"]["message"])
        make_request.assert_not_called()

        response = self.client.post("/v1/messages", headers=self.ANTHROPIC_HEADERS, json={**self.BODY, "model": "nosuch:model"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["type"], "invalid_request_error")

    def test_claude_code_beta_query_flag_is_not_forwarded(self):
        response, make_request = self.post(
            "/v1/messages?beta=true", self.BODY, headers=self.ANTHROPIC_HEADERS, upstream=json_upstream(CHAT_COMPLETION)
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("beta", dict(make_request.call_args.kwargs["params"] or {}))

        self.app.config.update(FREE_ROUTE_FREE_TIER_PROVIDERS="", FREE_ROUTE_PROVIDER_ORDER="")
        rows = [{"id": "opencode:hy3-free", "provider": "opencode", "model": "hy3-free", "status": "available", "provider_metadata": {}}]
        with (
            patch("services.free_model_policy.build_model_catalog", return_value=rows),
            patch.object(self.app_module.AuthService, "get_api_key", side_effect={"opencode": "free-key"}.get),
        ):
            response, _ = self.post(
                "/v1/messages?beta=true",
                {"model": "free:text", "max_tokens": 32, "messages": [{"role": "user", "content": "hi"}]},
                headers=self.ANTHROPIC_HEADERS,
                upstream=json_upstream(CHAT_COMPLETION),
            )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json()["content"], [{"type": "text", "text": "Hello"}])

    def test_model_discovery_accepts_x_api_key(self):
        response = self.client.get("/v1/models?limit=1000", headers={"x-api-key": "admin-test-key"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["data"])

    def test_count_tokens_is_a_local_estimate(self):
        with patch("app.ProxyService.make_request") as make_request:
            response = self.client.post(
                "/v1/messages/count_tokens",
                headers=self.ANTHROPIC_HEADERS,
                json={"model": "auto:claude-code", "system": "x" * 400, "messages": [{"role": "user", "content": "hello"}]},
            )
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.get_json()["input_tokens"], 100)
        self.assertEqual(response.headers["X-MultiLLM-Token-Count"], "estimate")
        make_request.assert_not_called()
