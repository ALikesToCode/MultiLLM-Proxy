import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests
from flask import Response


class UnifiedApiRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "OPENCODE_API_KEY": "opencode-provider-key",
                "MIMO_API_KEY": "mimo-provider-key",
                "LINKAPI_KEY": "linkapi-provider-key",
                "CODEX_EASY_API_KEY": "codex-easy-provider-key",
                "AUTH_DB_PATH": os.path.join(self.temp_dir.name, "auth.sqlite3"),
                "RATE_LIMIT_DB_PATH": os.path.join(self.temp_dir.name, "limits.sqlite3"),
                "MODEL_REGISTRY_DB_PATH": os.path.join(self.temp_dir.name, "models.sqlite3"),
            }
        )

        for module_name in list(sys.modules):
            if module_name.startswith(("routes.", "providers.")):
                sys.modules.pop(module_name, None)
        for module_name in (
            "app",
            "route_helpers",
            "services.auth_service",
            "services.model_registry",
            "services.rate_limit_service",
        ):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.config_module = importlib.import_module("config")
        self.original_gemini_models = list(self.config_module.Config.GEMINI_MODELS)
        self.config_module.Config.GEMINI_MODELS = ["gemini-test-model"]
        self.app = self.app_module.create_app()
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def tearDown(self):
        self.config_module.Config.GEMINI_MODELS = self.original_gemini_models
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    @staticmethod
    def _chat_response(text="ok"):
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(
            {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [
                    {
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"total_tokens": 3},
            }
        ).encode("utf-8")
        response.headers["Content-Type"] = "application/json"
        return response

    def test_v1_models_lists_provider_prefixed_models(self):
        response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )

        self.assertEqual(response.status_code, 200)
        model_ids = {model["id"] for model in response.get_json()["data"]}
        self.assertIn("opencode:kimi-k2.6", model_ids)
        self.assertIn("opencode:mimo-v2-pro", model_ids)
        self.assertIn("opencode:glm-5.1", model_ids)
        self.assertIn("opencode:qwen3.6-plus", model_ids)
        self.assertIn("mimo:mimo-v2.5-pro", model_ids)
        self.assertIn("gemini:gemini-test-model", model_ids)

    def test_v1_chat_completions_routes_provider_model(self):
        upstream_response = self._chat_response("hello")

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.6",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "hello")
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "opencode")
        self.assertEqual(
            request_kwargs["url"],
            "https://opencode.ai/zen/go/v1/chat/completions",
        )
        upstream_payload = json.loads(request_kwargs["data"])
        self.assertEqual(upstream_payload["model"], "kimi-k2.6")
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer opencode-provider-key",
        )

    def test_v1_chat_completions_routes_other_opencode_go_model(self):
        upstream_response = self._chat_response("hello")

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:mimo-v2-pro",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        upstream_payload = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual(upstream_payload["model"], "mimo-v2-pro")

    def test_v1_chat_completions_routes_mimo_token_plan_model(self):
        upstream_response = self._chat_response("hello")

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "mimo:mimo-v2.5-pro",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "mimo")
        self.assertEqual(
            request_kwargs["url"],
            "https://token-plan-sgp.xiaomimimo.com/v1/chat/completions",
        )
        upstream_payload = json.loads(request_kwargs["data"])
        self.assertEqual(upstream_payload["model"], "mimo-v2.5-pro")
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer mimo-provider-key",
        )

    def test_v1_chat_model_resolution_does_not_list_entire_registry(self):
        upstream_response = self._chat_response("hello")

        with patch("app.ProxyService.make_request", return_value=upstream_response), patch(
            "routes.unified.ModelRegistry.list_models",
            side_effect=AssertionError("list_models should not run on chat request"),
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.6",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)

    def test_v1_chat_requires_provider_prefixed_model(self):
        response = self.client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer admin-test-key"},
            json={"model": "kimi-k2.5", "messages": []},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("provider:model", response.get_json()["message"])

    def test_admin_can_disable_model_and_v1_chat_blocks_it(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

        disable_response = self.client.post("/admin/models/opencode:kimi-k2.6/disable")
        self.assertEqual(disable_response.status_code, 200)
        self.assertEqual(disable_response.get_json()["status"], "disabled")

        response = self.client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer admin-test-key"},
            json={
                "model": "opencode:kimi-k2.6",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("disabled", response.get_json()["message"])

    def test_admin_disable_unknown_model_returns_404(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

        response = self.client.post(
            "/admin/models/opencode:not-a-model/disable",
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn("Model not found", response.get_json()["message"])

    def test_admin_model_disable_requires_csrf_when_enabled(self):
        self.app.config["WTF_CSRF_ENABLED"] = True
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

        response = self.client.post("/admin/models/opencode:kimi-k2.6/disable")

        self.assertEqual(response.status_code, 400)

    def test_v1_responses_bridges_to_chat_completions(self):
        upstream_response = self._chat_response("response text")

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.6",
                    "instructions": "Be brief",
                    "input": "Say hi",
                    "max_output_tokens": 12,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["object"], "response")
        self.assertEqual(payload["output_text"], "response text")

        upstream_payload = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual(upstream_payload["model"], "kimi-k2.6")
        self.assertEqual(upstream_payload["max_tokens"], 12)
        self.assertEqual(
            upstream_payload["messages"],
            [
                {"role": "system", "content": "Be brief"},
                {"role": "user", "content": "Say hi"},
            ],
        )

    def test_v1_responses_treats_success_non_json_upstream_as_provider_failure(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = b"<html>bad gateway</html>"
        upstream_response.headers["Content-Type"] = "text/html"

        with patch("app.ProxyService.make_request", return_value=upstream_response):
            response = self.client.post(
                "/v1/responses",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Accept": "application/json",
                },
                json={
                    "model": "opencode:kimi-k2.6",
                    "input": "Say hi",
                },
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["error"], "internal_error")

    def test_v1_responses_passes_through_upstream_json_errors(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 429
        upstream_response._content = json.dumps(
            {"error": {"message": "provider rate limit"}}
        ).encode("utf-8")
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response):
            response = self.client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.6",
                    "input": "Say hi",
                },
            )

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.get_json()["error"]["message"], "provider rate limit")
        self.assertNotIn("object", response.get_json())

    def test_v1_responses_returns_flask_error_response_without_bridge(self):
        upstream_response = Response(
            json.dumps({"error": "circuit_open"}),
            status=503,
            content_type="application/json",
        )

        with patch("app.ProxyService.make_request", return_value=upstream_response):
            response = self.client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.6",
                    "input": "Say hi",
                },
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error"], "circuit_open")
        self.assertNotIn("object", response.get_json())

    def test_linkapi_responses_forwards_native_schema_and_model(self):
        native_body = (
            b'{  "id": "resp_test", "object": "response", '
            b'"status": "completed", "output": [] }\n'
        )
        upstream_response = requests.Response()
        upstream_response.status_code = 201
        upstream_response.raw = io.BytesIO(native_body)
        upstream_response.headers["Content-Type"] = "application/json"
        upstream_response.headers["Request-ID"] = "req_linkapi"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/responses?include=usage&include=output_text",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "linkapi:grok-4.5",
                    "input": "Say hi",
                    "max_output_tokens": 12,
                    "reasoning": {"effort": "high"},
                    "metadata": {"tenant": "test"},
                },
            )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, native_body)
        self.assertEqual(response.headers["Request-ID"], "req_linkapi")
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "linkapi")
        self.assertEqual(request_kwargs["url"], "https://api.linkapi.ai/v1/responses")
        self.assertEqual(
            request_kwargs["params"],
            [("include", "usage"), ("include", "output_text")],
        )
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer linkapi-provider-key",
        )
        self.assertEqual(
            json.loads(request_kwargs["data"]),
            {
                "model": "grok-4.5",
                "input": "Say hi",
                "max_output_tokens": 12,
                "reasoning": {"effort": "high"},
                "metadata": {"tenant": "test"},
            },
        )

    def test_linkapi_chat_preserves_grok_high_reasoning_and_conversation_affinity(self):
        native_body = b'{"id":"chatcmpl_linkapi_grok","object":"chat.completion","choices":[]}'
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response.raw = io.BytesIO(native_body)
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/chat/completions?trace=one&trace=two",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "X-Api-Key": "caller-key-must-not-leak",
                    "X-Grok-Conv-Id": "conversation-123",
                },
                json={
                    "model": "linkapi:grok-4.5",
                    "messages": [{"role": "user", "content": "Solve this"}],
                    "reasoning_effort": "high",
                    "metadata": {"tenant": "test"},
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_body)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "linkapi")
        self.assertEqual(
            request_kwargs["url"],
            "https://api.linkapi.ai/v1/chat/completions",
        )
        self.assertEqual(
            request_kwargs["params"],
            [("trace", "one"), ("trace", "two")],
        )
        self.assertEqual(
            json.loads(request_kwargs["data"]),
            {
                "model": "grok-4.5",
                "messages": [{"role": "user", "content": "Solve this"}],
                "reasoning_effort": "high",
                "metadata": {"tenant": "test"},
            },
        )
        upstream_headers = {
            name.lower(): value for name, value in request_kwargs["headers"].items()
        }
        self.assertEqual(
            upstream_headers["authorization"],
            "Bearer linkapi-provider-key",
        )
        self.assertEqual(
            upstream_headers["x-grok-conv-id"],
            "conversation-123",
        )
        self.assertNotIn("x-api-key", upstream_headers)

    def test_codex_easy_responses_preserves_grok_high_reasoning_and_all_fields(self):
        native_body = b'{"id":"resp_grok","object":"response","status":"completed"}'
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response.raw = io.BytesIO(native_body)
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/responses?include=usage&include=output_text",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "codex-easy:grok-4.5",
                    "input": "Solve this",
                    "reasoning": {"effort": "high"},
                    "prompt_cache_key": "conversation-123",
                    "tools": [{"type": "web_search"}],
                    "metadata": {"tenant": "test"},
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_body)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "codex-easy")
        self.assertEqual(request_kwargs["url"], "https://codex-easy.ai/v1/responses")
        self.assertEqual(
            request_kwargs["params"],
            [("include", "usage"), ("include", "output_text")],
        )
        self.assertEqual(
            json.loads(request_kwargs["data"]),
            {
                "model": "grok-4.5",
                "input": "Solve this",
                "reasoning": {"effort": "high"},
                "prompt_cache_key": "conversation-123",
                "tools": [{"type": "web_search"}],
                "metadata": {"tenant": "test"},
            },
        )
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer codex-easy-provider-key",
        )

    def test_codex_easy_chat_preserves_grok_high_reasoning_and_all_fields(self):
        native_body = b'{"id":"chatcmpl_grok","object":"chat.completion","choices":[]}'
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response.raw = io.BytesIO(native_body)
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "codex-easy:grok-4.5",
                    "messages": [{"role": "user", "content": "Solve this"}],
                    "reasoning_effort": "high",
                    "parallel_tool_calls": False,
                    "metadata": {"tenant": "test"},
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_body)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "codex-easy")
        self.assertEqual(
            request_kwargs["url"],
            "https://codex-easy.ai/v1/chat/completions",
        )
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer codex-easy-provider-key",
        )
        self.assertEqual(
            json.loads(request_kwargs["data"]),
            {
                "model": "grok-4.5",
                "messages": [{"role": "user", "content": "Solve this"}],
                "reasoning_effort": "high",
                "parallel_tool_calls": False,
                "metadata": {"tenant": "test"},
            },
        )

    def test_linkapi_responses_stream_is_byte_for_byte_and_closes_upstream(self):
        native_sse = (
            b"event: response.output_text.delta\n"
            b'data: {"type":"response.output_text.delta","delta":"hello"}\n\n'
            b"event: response.completed\n"
            b'data: {"type":"response.completed","response":{"id":"resp_test"}}\n\n'
        )
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response.raw = io.BytesIO(native_sse)
        upstream_response.headers["Content-Type"] = "text/event-stream"

        with patch.object(upstream_response, "close") as close, patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ):
            response = self.client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "linkapi:gpt-live-model",
                    "input": "Say hi",
                    "stream": True,
                },
            )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, native_sse)

        close.assert_called_once()
        self.assertNotIn(b"[DONE]", response.data)

    def test_linkapi_native_catchall_replaces_gemini_query_key(self):
        native_sse = b'data: {"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}\n\n'
        native_request = b'{  "contents": [{"parts": [{"text": "hello"}]}] }\n'
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response.raw = io.BytesIO(native_sse)
        upstream_response.headers["Content-Type"] = "text/event-stream"

        with patch.object(upstream_response, "close") as close, patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/linkapi/v1beta/models/gemini-live:streamGenerateContent"
                "?alt=sse&alt=json&key=admin-test-key",
                data=native_request,
                content_type="application/json",
            )
            response_data = response.data

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_data, native_sse)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        close.assert_called_once()
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["data"], native_request)
        self.assertEqual(
            request_kwargs["params"],
            [
                ("alt", "sse"),
                ("alt", "json"),
            ],
        )
        self.assertNotIn("Authorization", request_kwargs["headers"])
        self.assertEqual(
            request_kwargs["headers"]["X-Goog-Api-Key"],
            "linkapi-provider-key",
        )

    def test_linkapi_native_catchall_replaces_claude_header_key(self):
        native_request = b'{  "model": "claude-live", "messages": [] }\n'
        native_response = b'{  "id": "msg_test", "type": "message" }\n'
        upstream_response = requests.Response()
        upstream_response.status_code = 202
        upstream_response.raw = io.BytesIO(native_response)
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/linkapi/v1/messages?beta=one&beta=two",
                headers={
                    "X-Api-Key": "admin-test-key",
                    "Anthropic-Beta": "prompt-caching-2024-07-31",
                },
                data=native_request,
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data, native_response)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["data"], native_request)
        self.assertEqual(request_kwargs["params"], [("beta", "one"), ("beta", "two")])
        self.assertEqual(request_kwargs["headers"]["X-Api-Key"], "linkapi-provider-key")
        self.assertEqual(request_kwargs["headers"]["Anthropic-Version"], "2023-06-01")
        self.assertEqual(
            request_kwargs["headers"]["Anthropic-Beta"],
            "prompt-caching-2024-07-31",
        )
        self.assertNotIn("Authorization", request_kwargs["headers"])

    def test_linkapi_native_catchall_rejects_decoded_query_and_fragment_delimiters(self):
        encoded_paths = (
            "/linkapi/v1/responses%3Fkey%3Dencoded-path-secret",
            "/linkapi/v1/responses%23encoded-path-fragment",
        )

        for encoded_path in encoded_paths:
            with self.subTest(encoded_path=encoded_path), patch(
                "app.ProxyService.make_request"
            ) as make_request, self.assertLogs("routes.proxy", level="ERROR") as logs:
                response = self.client.post(
                    encoded_path,
                    headers={"Authorization": "Bearer admin-test-key"},
                    json={"model": "gpt-live-model", "input": "hello"},
                )

            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.get_json()["message"], "Invalid LinkAPI path")
            make_request.assert_not_called()
            log_output = "\n".join(logs.output)
            self.assertNotIn("encoded-path-secret", log_output)
            self.assertNotIn("encoded-path-fragment", log_output)


if __name__ == "__main__":
    unittest.main()
