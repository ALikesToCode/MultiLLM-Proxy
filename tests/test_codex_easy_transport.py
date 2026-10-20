import importlib
import io
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import requests


class CodexEasyNativeRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "CODEX_EASY_API_KEY": "codex-easy-provider-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "AUTH_DB_PATH": os.path.join(self.temp_dir.name, "auth.sqlite3"),
                "RATE_LIMIT_DB_PATH": os.path.join(self.temp_dir.name, "limits.sqlite3"),
                "MODEL_REGISTRY_DB_PATH": os.path.join(
                    self.temp_dir.name,
                    "models.sqlite3",
                ),
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
            "services.proxy_service",
            "services.rate_limit_service",
        ):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.app = self.app_module.create_app()
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    @staticmethod
    def _raw_response(
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        response = requests.Response()
        response.status_code = status
        response.raw = io.BytesIO(body)
        response.headers["Content-Type"] = content_type
        response.headers.update(headers or {})
        return response

    def test_models_preserves_query_duplicates_and_safe_openai_headers(self):
        native_body = b'{  "object": "list", "data": [] }\n'
        upstream_response = self._raw_response(
            native_body,
            headers={
                "X-Request-ID": "req_codex_easy",
                "X-RateLimit-Limit-Requests": "100",
                "Retry-After": "2",
                "Set-Cookie": "upstream-session=secret",
                "Location": "https://codex-easy.ai/account",
            },
        )

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.get(
                "/codex-easy/v1/models?include=a&include=b&key=caller-one&KEY=caller-two",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "X-Api-Key": "caller-x-api-key",
                    "X-Goog-Api-Key": "caller-google-key",
                    "OpenAI-Organization": "org_test",
                    "OpenAI-Project": "proj_test",
                    "OpenAI-Beta": "responses=v1",
                    "Idempotency-Key": "idem_test",
                    "X-Client-Request-ID": "client_req_test",
                    "X-Stainless-Lang": "python",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_body)
        self.assertEqual(response.headers["X-Request-ID"], "req_codex_easy")
        self.assertEqual(response.headers["X-RateLimit-Limit-Requests"], "100")
        self.assertEqual(response.headers["Retry-After"], "2")
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertNotIn("Location", response.headers)

        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["url"], "https://codex-easy.ai/v1/models")
        self.assertEqual(
            request_kwargs["params"],
            [("include", "a"), ("include", "b")],
        )
        self.assertEqual(request_kwargs["data"], b"")
        self.assertEqual(request_kwargs["api_provider"], "codex-easy")
        self.assertFalse(request_kwargs["use_cache"])

        upstream_headers = {
            name.lower(): value for name, value in request_kwargs["headers"].items()
        }
        self.assertEqual(
            upstream_headers["authorization"],
            "Bearer codex-easy-provider-key",
        )
        self.assertNotIn("x-api-key", upstream_headers)
        self.assertNotIn("x-goog-api-key", upstream_headers)
        self.assertEqual(upstream_headers["openai-organization"], "org_test")
        self.assertEqual(upstream_headers["openai-project"], "proj_test")
        self.assertEqual(upstream_headers["openai-beta"], "responses=v1")
        self.assertEqual(upstream_headers["idempotency-key"], "idem_test")
        self.assertEqual(upstream_headers["x-client-request-id"], "client_req_test")
        self.assertEqual(upstream_headers["x-stainless-lang"], "python")

    def test_responses_sse_is_byte_for_byte_without_synthetic_done(self):
        request_body = (
            b'{  "model": "grok-4.5", "input": "hello", "stream": true }\n'
        )
        native_sse = (
            b"event: response.output_text.delta\n"
            b'data: {"type":"response.output_text.delta","delta":"hi"}\n\n'
            b"event: response.completed\n"
            b'data: {"type":"response.completed"}\n\n'
        )
        upstream_response = self._raw_response(
            native_sse,
            content_type="text/event-stream",
        )

        with patch.object(upstream_response, "close") as close, patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/codex-easy/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                data=request_body,
                content_type="application/json",
            )
            response_data = response.data

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_data, native_sse)
        self.assertNotIn(b"[DONE]", response_data)
        self.assertEqual(make_request.call_args.kwargs["data"], request_body)
        close.assert_called_once()

    def test_chat_completions_sse_is_byte_for_byte(self):
        request_body = (
            b'{"model":"grok-4.5","messages":[],"stream":true,'
            b'"reasoning_effort":"high"}'
        )
        native_sse = (
            b'data: {"id":"chatcmpl_test","choices":[{"delta":{"content":"hi"}}]}\n\n'
            b"data: [DONE]\n\n"
        )
        upstream_response = self._raw_response(
            native_sse,
            content_type="text/event-stream",
        )

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/codex-easy/v1/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "X-Api-Key": "caller-key-must-not-leak",
                    "X-Grok-Conv-Id": "conversation-123",
                },
                data=request_body,
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_sse)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["data"], request_body)
        upstream_headers = {
            name.lower(): value for name, value in request_kwargs["headers"].items()
        }
        self.assertEqual(
            upstream_headers["authorization"],
            "Bearer codex-easy-provider-key",
        )
        self.assertEqual(
            upstream_headers["x-grok-conv-id"],
            "conversation-123",
        )
        self.assertNotIn("x-api-key", upstream_headers)

    def test_image_multipart_and_binary_response_are_unchanged(self):
        boundary = "codex-easy-test-boundary"
        request_body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="model"\r\n\r\n'
            "image-group\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="image"; filename="input.png"\r\n'
            "Content-Type: image/png\r\n\r\n"
        ).encode("ascii") + b"\x89PNG\r\n\x1a\nraw" + f"\r\n--{boundary}--\r\n".encode(
            "ascii"
        )
        binary_body = b"\x89PNG\r\n\x1a\n\x00\x00generated-image"
        upstream_response = self._raw_response(
            binary_body,
            content_type="image/png",
            headers={"Content-Disposition": 'inline; filename="result.png"'},
        )

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/codex-easy/v1/images/edits",
                headers={"Authorization": "Bearer admin-test-key"},
                data=request_body,
                content_type=f"multipart/form-data; boundary={boundary}",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, binary_body)
        self.assertEqual(response.headers["Content-Type"], "image/png")
        self.assertEqual(
            response.headers["Content-Disposition"],
            'inline; filename="result.png"',
        )
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["data"], request_body)
        self.assertEqual(
            request_kwargs["headers"]["Content-Type"],
            f"multipart/form-data; boundary={boundary}",
        )

    def test_unsupported_paths_never_reach_upstream(self):
        paths = (
            "/codex-easy",
            "/codex-easy/v1",
            "/codex-easy/account",
            "/codex-easy/v1/models/",
            "/codex-easy/v1/responses/other",
            "/codex-easy/v1/images/%2E%2E/account",
        )

        for path in paths:
            with self.subTest(path=path), patch(
                "app.ProxyService.make_request"
            ) as make_request:
                response = self.client.post(
                    path,
                    headers={"Authorization": "Bearer admin-test-key"},
                    data=b"{}",
                    content_type="application/json",
                )

            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                response.get_json()["message"],
                "Invalid Codex Everywhere path",
            )
            make_request.assert_not_called()

    def test_decoded_query_or_fragment_in_path_is_rejected_without_logging_secret(self):
        paths = (
            "/codex-easy/v1/responses%3Fkey%3Dencoded-codex-secret",
            "/codex-easy/v1/responses%253Fkey%253Ddouble-encoded-codex-secret",
            "/codex-easy/v1/responses%23encoded-codex-fragment",
            "/codex-easy/v1/responses%2523double-encoded-codex-fragment",
            "/codex-easy/v1/images/%2e%2e/account",
            "/codex-easy/v1/images/%252e%252e/account",
            "/codex-easy/v1/images/%25literal-percent",
        )

        for path in paths:
            with self.subTest(path=path), patch(
                "app.ProxyService.make_request"
            ) as make_request, self.assertLogs("routes.proxy", level="ERROR") as logs:
                response = self.client.post(
                    path,
                    headers={"Authorization": "Bearer admin-test-key"},
                    data=b"{}",
                    content_type="application/json",
                )

            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                response.get_json()["message"],
                "Invalid Codex Everywhere path",
            )
            make_request.assert_not_called()
            log_output = "\n".join(logs.output)
            self.assertNotIn("encoded-codex-secret", log_output)
            self.assertNotIn("encoded-codex-fragment", log_output)
            self.assertNotIn("double-encoded-codex-secret", log_output)
            self.assertNotIn("double-encoded-codex-fragment", log_output)


class CodexEasyRawRequestServiceTest(unittest.TestCase):
    def setUp(self):
        sys.modules.pop("services.proxy_service", None)
        self.proxy_module = importlib.import_module("services.proxy_service")

    @staticmethod
    def _response(status: int, body: bytes = b'{}') -> requests.Response:
        response = requests.Response()
        response.status_code = status
        response._content = body
        response.headers["Content-Type"] = "application/json"
        return response

    def test_status_error_is_returned_once_without_retry_or_circuit_breaker(self):
        upstream_response = self._response(503, b'{"error":"busy"}')
        session = Mock()
        session.request.return_value = upstream_response

        with patch.object(
            self.proxy_module.ProxyService,
            "_get_provider_session",
            return_value=session,
        ), patch.object(
            self.proxy_module.ProxyService,
            "_circuit_open_response",
        ) as circuit_open, patch("services.proxy_service.time.sleep") as sleep:
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://codex-easy.ai/v1/responses",
                headers={"Idempotency-Key": "request-123"},
                params=[],
                data=b'{"model":"grok-4.5"}',
                api_provider="codex-easy",
                use_cache=False,
            )

        self.assertIs(response, upstream_response)
        self.assertEqual(session.request.call_count, 1)
        self.assertFalse(session.request.call_args.kwargs["allow_redirects"])
        circuit_open.assert_not_called()
        sleep.assert_not_called()

    def test_transport_error_is_generic_and_never_retried_or_leaked(self):
        secret = "codex-easy-upstream-secret"
        session = Mock()
        session.request.side_effect = requests.exceptions.ConnectTimeout(
            f"timed out with Authorization: Bearer {secret}"
        )

        with patch.object(
            self.proxy_module.ProxyService,
            "_get_provider_session",
            return_value=session,
        ), patch("services.proxy_service.time.sleep") as sleep, self.assertLogs(
            "services.proxy_service",
            level="ERROR",
        ) as logs:
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://codex-easy.ai/v1/responses",
                headers={"Authorization": f"Bearer {secret}"},
                params=[],
                data=b'{"model":"grok-4.5"}',
                api_provider="codex-easy",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(session.request.call_count, 1)
        sleep.assert_not_called()
        serialized_response = response.content + repr(dict(response.headers)).encode()
        log_output = "\n".join(logs.output)
        self.assertNotIn(secret.encode(), serialized_response)
        self.assertNotIn(secret, log_output)
        self.assertNotIn("Authorization", log_output)

    def test_make_request_does_not_decode_or_normalize_multipart_body(self):
        multipart_body = b"--boundary\r\n\xff\x00raw\r\n--boundary--\r\n"
        upstream_response = self._response(200)

        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=upstream_response,
        ) as make_base_request:
            response = self.proxy_module.ProxyService.make_request(
                method="POST",
                url="https://codex-easy.ai/v1/images/edits",
                headers={"Content-Type": "multipart/form-data; boundary=boundary"},
                params=[],
                data=multipart_body,
                api_provider="codex-easy",
                use_cache=False,
            )

        self.assertIs(response, upstream_response)
        self.assertEqual(make_base_request.call_args.kwargs["data"], multipart_body)

    def test_linkapi_chat_forwards_canonical_grok_cache_affinity_header(self):
        headers = self.proxy_module.ProxyService.prepare_headers(
            {
                "Authorization": "Bearer caller-key-must-not-leak",
                "X-Api-Key": "caller-key-must-not-leak",
                "x-grok-conv-id": "conversation-123",
            },
            "linkapi",
            "linkapi-provider-key",
            upstream_path="/v1/chat/completions",
        )

        self.assertEqual(headers["X-Grok-Conv-Id"], "conversation-123")
        self.assertEqual(
            headers["Authorization"],
            "Bearer linkapi-provider-key",
        )
        self.assertNotIn("X-Api-Key", headers)

    def test_linkapi_non_chat_protocols_drop_grok_cache_affinity_header(self):
        for upstream_path in (
            "v1/responses",
            "v1/messages",
            "v1beta/models/gemini-test:generateContent",
        ):
            with self.subTest(upstream_path=upstream_path):
                headers = self.proxy_module.ProxyService.prepare_headers(
                    {"X-Grok-Conv-Id": "conversation-123"},
                    "linkapi",
                    "linkapi-provider-key",
                    upstream_path=upstream_path,
                )

                self.assertNotIn(
                    "x-grok-conv-id",
                    {name.lower() for name in headers},
                )

    def test_pooled_raw_session_never_stores_or_replays_upstream_cookies(self):
        received_cookies: dict[str, list[str | None]] = {
            "raw": [],
            "normal": [],
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                provider_kind, request_kind = self.path.strip("/").split("/", 1)
                received_cookies[provider_kind].append(self.headers.get("Cookie"))
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if request_kind == "first":
                    self.send_header(
                        "Set-Cookie",
                        f"{provider_kind}_sticky=provider-secret; Path=/",
                    )
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                return

        proxy_service = self.proxy_module.ProxyService
        provider_names = ("codex-easy", "normal-cookie-test")
        with proxy_service._session_lock:
            for provider_name in provider_names:
                previous_session = proxy_service._sessions.pop(provider_name, None)
                if previous_session is not None:
                    previous_session.close()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            raw_session = proxy_service._get_provider_session("codex-easy")
            for request_kind in ("first", "second"):
                response = proxy_service._make_base_request(
                    method="GET",
                    url=(
                        f"http://127.0.0.1:{server.server_port}/raw/{request_kind}"
                    ),
                    headers={},
                    params=[],
                    data=None,
                    api_provider="codex-easy",
                    use_cache=False,
                )
                self.assertEqual(response.content, b"{}")
                response.close()

            self.assertIs(
                proxy_service._get_provider_session("codex-easy"),
                raw_session,
            )
            self.assertEqual(list(raw_session.cookies), [])

            normal_session = proxy_service._get_provider_session(
                "normal-cookie-test"
            )
            for request_kind in ("first", "second"):
                response = proxy_service._make_base_request(
                    method="GET",
                    url=(
                        f"http://127.0.0.1:{server.server_port}/normal/{request_kind}"
                    ),
                    headers={},
                    params=[],
                    data=None,
                    api_provider="normal-cookie-test",
                    use_cache=False,
                )
                self.assertEqual(response.content, b"{}")
                response.close()

            self.assertIs(
                proxy_service._get_provider_session("normal-cookie-test"),
                normal_session,
            )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)
            with proxy_service._session_lock:
                for provider_name in provider_names:
                    session = proxy_service._sessions.pop(provider_name, None)
                    if session is not None:
                        session.close()

        self.assertEqual(received_cookies["raw"], [None, None])
        self.assertEqual(received_cookies["normal"][0], None)
        self.assertIn(
            "normal_sticky=provider-secret",
            received_cookies["normal"][1] or "",
        )


if __name__ == "__main__":
    unittest.main()
