import importlib
import json
import os
import sys
import time
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

    def test_login_page_advertises_pwa_manifest(self):
        response = self.client.get("/login")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn('rel="manifest"', html)
        self.assertIn("/manifest.webmanifest", html)
        self.assertIn("/apple-touch-icon.png", html)

    def test_manifest_route_serves_install_metadata(self):
        response = self.client.get("/manifest.webmanifest")

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/manifest+json", response.content_type)
        manifest = response.get_json()
        self.assertEqual(manifest["name"], "MultiLLM Proxy")
        self.assertEqual(manifest["display"], "standalone")
        self.assertEqual(manifest["start_url"], "/")
        self.assertTrue(any(icon["sizes"] == "192x192" for icon in manifest["icons"]))
        self.assertTrue(any(icon["sizes"] == "512x512" for icon in manifest["icons"]))

    def test_service_worker_route_is_root_scoped(self):
        response = self.client.get("/service-worker.js")

        self.assertEqual(response.status_code, 200)
        self.assertIn("javascript", response.content_type)
        self.assertEqual(response.headers.get("Service-Worker-Allowed"), "/")
        script = response.get_data(as_text=True)
        self.assertIn("self.addEventListener('install'", script)
        self.assertIn("offline.html", script)

    def test_status_json_includes_dashboard_analytics(self):
        metrics_service = self.app_module.MetricsService.get_instance()
        metrics_service.requests.clear()
        current_time = time.time()
        metrics_service.track_request("openai", 200, 120, timestamp=current_time - 30)
        metrics_service.track_request("openrouter", 500, 450, timestamp=current_time - 15)

        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key": "admin-test-key",
            }

        with patch("app.check_provider", side_effect=lambda provider, details, app_config: {
            "name": provider.upper(),
            "active": True,
            "description": details.get("description", ""),
            "requests_24h": 1,
            "success_rate": 100.0,
            "avg_latency": 120.0,
            "p95_latency": 120.0,
            "error_rate": 0.0,
        }):
            response = self.client.get("/", headers={"Accept": "application/json"})

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("analytics", payload)
        self.assertIn("provider_breakdown", payload["analytics"])
        self.assertIn("recent_failures", payload["analytics"])
        self.assertIn("traffic_series", payload["stats"])
        self.assertEqual(payload["stats"]["failed_requests"], 1)

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

    def test_streaming_route_strips_embedded_chunk_json_from_raw_upstream_lines(self):
        mixed_chunk = (
            "She's a Desi queen trying to maintain her respectable married image while falling apart~ "
            "(ï½¡•́ï¸¿•̀ï½¡)\n\n"
            "Ready to resume whenever Human is! Just say the word and Celia will dive back into the "
            "simulation! (ﾉ>ω<)ﾉ :ï½¡ï½¥:*:ï½¥ﾟ’"
            '{"id":"gen-1776050894-GzfFOVxmNQJqMtzO6fHn","object":"chat.completion.chunk",'
            '"created":1776050894,"model":"moonshotai/kimi-k2.5-0127","provider":"Moonshot AI",'
            '"system_fingerprint":"fpv0_ec10c667","choices":[{"index":0,"delta":{"content":"â",'
            '"role":"assistant"},"finish_reason":null,"native_finish_reason":null}]}-'
        )

        class FakeRawStreamingResponse:
            status_code = 200
            headers = {"content-type": "text/event-stream"}

            def iter_lines(self, decode_unicode=True):
                yield mixed_chunk
                yield "data: [DONE]"

            def close(self):
                return None

        with patch("app.ProxyService.make_request", return_value=FakeRawStreamingResponse()):
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
        chunks = [chunk for chunk in response.get_data(as_text=True).split("\n\n") if chunk]
        first_chunk = json.loads(chunks[0][6:])
        content = first_chunk["choices"][0]["delta"]["content"]
        self.assertIn(
            "She's a Desi queen trying to maintain her respectable married image while falling apart",
            content,
        )
        self.assertIn("Ready to resume whenever Human is!", content)
        self.assertNotIn("chat.completion.chunk", content)
        self.assertNotIn("gen-1776050894", content)
        self.assertEqual(chunks[1], "data: [DONE]")


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
            closed = False

            def iter_lines(self, decode_unicode=True):
                yield 'data: {"choices":[{"delta":{"content":"Hello"}}]}'
                yield "data: [DONE]"
                yield 'data: {"choices":[{"delta":{"content":"should not arrive"}}]}'

            def close(self):
                self.closed = True

        fake_response = FakeStreamingResponse()
        chunks = list(
            self.proxy_module.ProxyService._create_streaming_response(
                fake_response,
                "opencode",
            )
        )

        self.assertEqual(len(chunks), 2)
        first_chunk = json.loads(chunks[0][6:].strip())
        self.assertEqual(first_chunk["choices"][0]["delta"]["content"], "Hello")
        self.assertEqual(chunks[1], "data: [DONE]\n\n")
        self.assertTrue(fake_response.closed)

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

    def test_make_base_request_rewrites_brotli_accept_encoding(self):
        fake_response = requests.Response()
        fake_response.status_code = 200
        fake_response._content = json.dumps(
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
        fake_response.headers["Content-Type"] = "application/json"

        with patch("services.proxy_service.requests.Session.request", return_value=fake_response) as request_mock:
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://opencode.ai/zen/go/v1/chat/completions",
                headers={
                    "Authorization": "Bearer provider-key",
                    "Content-Type": "application/json",
                    "Accept-Encoding": "gzip, br",
                },
                params={},
                data=json.dumps({"stream": False}).encode("utf-8"),
                api_provider="opencode",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            request_mock.call_args.kwargs["headers"]["Accept-Encoding"],
            "gzip, deflate",
        )
        self.assertEqual(request_mock.call_args.kwargs["timeout"], (5, 120))

    def test_special_provider_get_requests_do_not_require_json_body(self):
        fake_response = requests.Response()
        fake_response.status_code = 200
        fake_response._content = b'{"data":[]}'
        fake_response.headers["Content-Type"] = "application/json"

        for provider in ("together", "groq", "googleai", "nineteen"):
            with self.subTest(provider=provider):
                with patch.object(
                    self.proxy_module.ProxyService,
                    "_make_base_request",
                    return_value=fake_response,
                ) as base_request:
                    response = self.proxy_module.ProxyService.make_request(
                        method="GET",
                        url="https://example.invalid/v1/models",
                        headers={},
                        params={},
                        data=None,
                        api_provider=provider,
                        use_cache=False,
                    )

                self.assertEqual(response.status_code, 200)
                base_request.assert_called()

    def test_make_base_request_retries_opencode_timeout_payloads(self):
        timeout_response = requests.Response()
        timeout_response.status_code = 400
        timeout_response._content = json.dumps(
            {
                "error": {
                    "message": "timeout",
                    "code": 400,
                },
                "user_id": "user_2z4xm5LomaIHfsnVqMhFsWrVrGY",
            }
        ).encode("utf-8")
        timeout_response.headers["Content-Type"] = "application/json"

        success_response = requests.Response()
        success_response.status_code = 200
        success_response._content = json.dumps(
            {
                "id": "chatcmpl-opencode-retry",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Recovered after retry"},
                        "finish_reason": "stop",
                    }
                ],
            }
        ).encode("utf-8")
        success_response.headers["Content-Type"] = "application/json"

        with patch(
            "services.proxy_service.requests.Session.request",
            side_effect=[timeout_response, success_response],
        ) as request_mock:
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://opencode.ai/zen/go/v1/chat/completions",
                headers={
                    "Authorization": "Bearer provider-key",
                    "Content-Type": "application/json",
                },
                params={},
                data=json.dumps({"stream": False}).encode("utf-8"),
                api_provider="opencode",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["choices"][0]["message"]["content"], "Recovered after retry")
        self.assertEqual(request_mock.call_count, 2)


if __name__ == "__main__":
    unittest.main()
