import importlib
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests


class KimiCodeNativeRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "KIMI_CODE_API_KEY": "kimi-code-provider-key",
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

    def test_models_uses_exact_url_and_preserves_only_safe_headers_and_query(self):
        native_body = b'{  "object": "list", "data": [] }\n'
        upstream_response = self._raw_response(
            native_body,
            headers={
                "X-Request-ID": "req_kimi_code",
                "X-RateLimit-Limit-Requests": "100",
                "Retry-After": "2",
                "Set-Cookie": "upstream-session=secret",
                "Location": "https://api.kimi.com/account",
            },
        )

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.get(
                "/kimi-code/v1/models?include=a&include=b&key=caller-one&KEY=caller-two",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "X-Api-Key": "caller-x-api-key",
                    "X-Goog-Api-Key": "caller-google-key",
                    "User-Agent": "KimiCLI/1.2.3",
                    "OpenAI-Organization": "org_test",
                    "OpenAI-Project": "proj_test",
                    "OpenAI-Beta": "chat=v1",
                    "Idempotency-Key": "idem_test",
                    "X-Client-Request-ID": "client_req_test",
                    "X-Stainless-Lang": "python",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_body)
        self.assertEqual(response.headers["X-Request-ID"], "req_kimi_code")
        self.assertEqual(response.headers["X-RateLimit-Limit-Requests"], "100")
        self.assertEqual(response.headers["Retry-After"], "2")
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertNotIn("Location", response.headers)

        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(
            request_kwargs["url"],
            "https://api.kimi.com/coding/v1/models",
        )
        self.assertEqual(
            request_kwargs["params"],
            [("include", "a"), ("include", "b")],
        )
        self.assertEqual(request_kwargs["data"], b"")
        self.assertEqual(request_kwargs["api_provider"], "kimi-code")
        self.assertFalse(request_kwargs["use_cache"])

        upstream_headers = {
            name.lower(): value for name, value in request_kwargs["headers"].items()
        }
        self.assertEqual(
            upstream_headers["authorization"],
            "Bearer kimi-code-provider-key",
        )
        self.assertNotIn("x-api-key", upstream_headers)
        self.assertNotIn("x-goog-api-key", upstream_headers)
        self.assertEqual(upstream_headers["user-agent"], "KimiCLI/1.2.3")
        self.assertEqual(upstream_headers["openai-organization"], "org_test")
        self.assertEqual(upstream_headers["openai-project"], "proj_test")
        self.assertEqual(upstream_headers["openai-beta"], "chat=v1")
        self.assertEqual(upstream_headers["idempotency-key"], "idem_test")
        self.assertEqual(upstream_headers["x-client-request-id"], "client_req_test")
        self.assertEqual(upstream_headers["x-stainless-lang"], "python")

    def test_chat_sse_and_k3_reasoning_history_are_byte_for_byte(self):
        request_body = (
            b'{"model":"k3","messages":[{"role":"assistant",'
            b'"content":"","reasoning_content":"thinking",'
            b'"tool_calls":[{"id":"call_1","type":"function",'
            b'"function":{"name":"lookup","arguments":"{}"}}]},'
            b'{"role":"tool","tool_call_id":"call_1","content":"ok"}],'
            b'"reasoning_effort":"max","prompt_cache_key":"session-123",'
            b'"stream":true}'
        )
        native_sse = (
            b'data: {"id":"chatcmpl_test","choices":[{"delta":'
            b'{"reasoning_content":"work"}}]}\n\n'
            b'data: {"id":"chatcmpl_test","choices":[{"delta":{"content":"hi"}}]}\n\n'
            b"data: [DONE]\n\n"
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
                "/kimi-code/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                data=request_body,
                content_type="application/json",
            )
            response_data = response.data

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_data, native_sse)
        self.assertEqual(make_request.call_args.kwargs["data"], request_body)
        close.assert_called_once()

    def test_unsupported_and_encoded_paths_never_reach_upstream(self):
        paths = (
            "/kimi-code",
            "/kimi-code/v1",
            "/kimi-code/account",
            "/kimi-code/v1/models/",
            "/kimi-code/v1/responses",
            "/kimi-code/v1/chat/completions/extra",
            "/kimi-code/v1%2Fmodels",
            "/kimi-code%2Fv1/models",
            "/kimi-code%252Fv1/models",
            "/kimi-code/v1/models%3Fkey%3Dencoded-kimi-secret",
            "/kimi-code/v1/models%253Fkey%253Ddouble-encoded-kimi-secret",
            "/kimi-code/v1/models%23encoded-kimi-fragment",
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
            self.assertEqual(response.get_json()["message"], "Invalid Kimi Code path")
            make_request.assert_not_called()

    def test_unified_chat_preserves_k3_fields_and_uses_raw_transport(self):
        native_body = b'{"id":"chatcmpl_k3","object":"chat.completion","choices":[]}'
        upstream_response = self._raw_response(native_body)

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request:
            response = self.client.post(
                "/v1/chat/completions?trace=one&trace=two&key=caller-secret",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "User-Agent": "KimiCLI/1.2.3",
                },
                json={
                    "model": "kimi-code:k3",
                    "messages": [{"role": "user", "content": "Solve this"}],
                    "reasoning_effort": "max",
                    "prompt_cache_key": "session-123",
                    "parallel_tool_calls": False,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, native_body)
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "kimi-code")
        self.assertEqual(
            request_kwargs["url"],
            "https://api.kimi.com/coding/v1/chat/completions",
        )
        self.assertEqual(
            request_kwargs["params"],
            [("trace", "one"), ("trace", "two")],
        )
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer kimi-code-provider-key",
        )
        self.assertEqual(
            __import__("json").loads(request_kwargs["data"]),
            {
                "model": "k3",
                "messages": [{"role": "user", "content": "Solve this"}],
                "reasoning_effort": "max",
                "prompt_cache_key": "session-123",
                "parallel_tool_calls": False,
            },
        )

    def test_unified_responses_explicitly_rejects_undocumented_protocol(self):
        with patch("app.ProxyService.make_request") as make_request:
            response = self.client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "kimi-code:k3",
                    "input": "Say hi",
                    "reasoning": {"effort": "max"},
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["message"],
            "Kimi Code does not support the Responses API; use /v1/chat/completions",
        )
        make_request.assert_not_called()


class KimiCodeRawRequestServiceTest(unittest.TestCase):
    def setUp(self):
        sys.modules.pop("services.proxy_service", None)
        self.proxy_module = importlib.import_module("services.proxy_service")

    @staticmethod
    def _response(status: int, body: bytes = b"{}") -> requests.Response:
        response = requests.Response()
        response.status_code = status
        response._content = body
        response.headers["Content-Type"] = "application/json"
        return response

    def test_status_error_is_returned_once_without_retry_redirect_or_circuit(self):
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
                url="https://api.kimi.com/coding/v1/chat/completions",
                headers={"Idempotency-Key": "request-123"},
                params=[],
                data=b'{"model":"k3"}',
                api_provider="kimi-code",
                use_cache=False,
            )

        self.assertIs(response, upstream_response)
        self.assertEqual(session.request.call_count, 1)
        self.assertFalse(session.request.call_args.kwargs["allow_redirects"])
        circuit_open.assert_not_called()
        sleep.assert_not_called()

    def test_transport_error_is_generic_and_never_retried_or_leaked(self):
        secret = "kimi-code-upstream-secret"
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
                url="https://api.kimi.com/coding/v1/chat/completions",
                headers={"Authorization": f"Bearer {secret}"},
                params=[],
                data=b'{"model":"k3"}',
                api_provider="kimi-code",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json()["error"]["message"],
            "Kimi Code upstream transport request failed",
        )
        self.assertEqual(session.request.call_count, 1)
        sleep.assert_not_called()
        serialized_response = response.content + repr(dict(response.headers)).encode()
        log_output = "\n".join(logs.output)
        self.assertNotIn(secret.encode(), serialized_response)
        self.assertNotIn(secret, log_output)
        self.assertNotIn("Authorization", log_output)


if __name__ == "__main__":
    unittest.main()
