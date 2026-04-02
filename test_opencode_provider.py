import importlib
import json
import os
import sys
import unittest
from unittest.mock import patch

import requests
from flask import Response


class OpenCodeProviderRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        os.environ["ADMIN_API_KEY"] = "admin-test-key"
        os.environ["FLASK_SECRET_KEY"] = "flask-test-secret"
        os.environ["JWT_SECRET"] = "jwt-test-secret"
        os.environ["OPENCODE_API_KEY"] = "opencode-provider-key"

        for module_name in ("app", "services.auth_service", "services.proxy_service"):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.auth_module = importlib.import_module("services.auth_service")
        self.auth_module.AuthService._users = {}
        self.auth_module.AuthService._api_keys = {}
        self.auth_module.AuthService.initialize()

        self.client = self.app_module.create_app().test_client()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_opencode_chat_completions_routes_to_go_endpoint(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = json.dumps(
            {
                "id": "chatcmpl-opencode",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello from OpenCode"},
                        "finish_reason": "stop",
                    }
                ],
            }
        ).encode("utf-8")
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/opencode/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Content-Type": "application/json",
                    "Origin": "https://example.com",
                },
                json={
                    "model": "kimi-k2.5",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "max_tokens": 128,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "Hello from OpenCode")
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://example.com")

        make_request.assert_called_once()
        self.assertEqual(
            make_request.call_args.kwargs["url"],
            "https://opencode.ai/zen/go/v1/chat/completions",
        )
        self.assertEqual(make_request.call_args.kwargs["api_provider"], "opencode")
        self.assertEqual(
            make_request.call_args.kwargs["headers"]["Authorization"],
            "Bearer opencode-provider-key",
        )

    def test_proxy_preflight_returns_cors_headers(self):
        response = self.client.open(
            "/opencode/chat/completions",
            method="OPTIONS",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://example.com")
        self.assertIn("POST", response.headers["Access-Control-Allow-Methods"])
        self.assertIn("Authorization", response.headers["Access-Control-Allow-Headers"])

    def test_streaming_proxy_response_is_returned_without_rewrapping(self):
        upstream_stream = Response(
            'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\ndata: [DONE]\n\n',
            status=200,
            mimetype="text/event-stream",
        )

        with patch("app.ProxyService.make_request", return_value=upstream_stream):
            response = self.client.post(
                "/opencode/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Content-Type": "application/json",
                    "Origin": "https://example.com",
                },
                json={
                    "model": "kimi-k2.5",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "max_tokens": 128,
                    "stream": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://example.com")
        self.assertIn('data: {"choices":[{"delta":{"content":"Hello"}}]}', response.get_data(as_text=True))
        self.assertIn("data: [DONE]", response.get_data(as_text=True))


class ProxyServiceStreamingNormalizationTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        os.environ["ADMIN_API_KEY"] = "admin-test-key"
        os.environ["FLASK_SECRET_KEY"] = "flask-test-secret"
        os.environ["JWT_SECRET"] = "jwt-test-secret"
        os.environ["OPENCODE_API_KEY"] = "opencode-provider-key"

        for module_name in ("services.proxy_service", "services.auth_service"):
            sys.modules.pop(module_name, None)

        self.proxy_module = importlib.import_module("services.proxy_service")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_streaming_normalizer_skips_comments_and_preserves_sse_boundaries(self):
        class FakeStreamingResponse:
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self, decode_unicode=True):
                yield ": OPENROUTER PROCESSING"
                yield ""
                yield 'data: {"choices":[{"delta":{"content":"Hello"}}]}'
                yield ""
                yield "data: [DONE]"

        chunks = list(
            self.proxy_module.ProxyService._create_streaming_response(
                FakeStreamingResponse(),
                "opencode",
            )
        )

        first_chunk = json.loads(chunks[0][6:].strip())
        self.assertEqual(first_chunk["choices"][0]["delta"]["content"], "Hello")
        self.assertEqual(chunks[1], "data: [DONE]\n\n")

    def test_streaming_normalizer_stops_after_done_marker(self):
        class FakeStreamingResponse:
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self, decode_unicode=True):
                yield 'data: {"choices":[{"delta":{"content":"Hello"}}]}'
                yield "data: [DONE]"
                yield 'data: {"choices":[{"delta":{"content":"should not arrive"}}]}'

        chunks = list(
            self.proxy_module.ProxyService._create_streaming_response(
                FakeStreamingResponse(),
                "opencode",
            )
        )

        self.assertEqual(len(chunks), 2)
        first_chunk = json.loads(chunks[0][6:].strip())
        self.assertEqual(first_chunk["choices"][0]["delta"]["content"], "Hello")
        self.assertEqual(chunks[1], "data: [DONE]\n\n")

    def test_openrouter_streaming_handler_stops_after_done_marker(self):
        class FakeStreamingResponse:
            status_code = 200
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self):
                yield b'data: {"choices":[{"delta":{"content":"Hello"}}]}'
                yield b"data: [DONE]"
                yield b'data: {"choices":[{"delta":{"content":"should not arrive"}}]}'

        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=FakeStreamingResponse(),
        ):
            response = self.proxy_module.ProxyService._handle_openrouter_request(
                method="POST",
                url="https://opencode.ai/zen/go/v1/chat/completions",
                headers={"Authorization": "Bearer provider-key"},
                params={},
                data=json.dumps({"stream": True}).encode("utf-8"),
                request_data={"stream": True},
                use_cache=False,
                auth_token="provider-key",
            )

        chunks = list(response.response)
        self.assertEqual(len(chunks), 2)
        first_chunk = json.loads(chunks[0][6:].strip())
        self.assertEqual(first_chunk["choices"][0]["delta"]["content"], "Hello")
        self.assertEqual(chunks[1], "data: [DONE]\n\n")


if __name__ == "__main__":
    unittest.main()
