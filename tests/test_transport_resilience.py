import importlib
import json
import os
import sys
import unittest
from unittest.mock import Mock, patch

import requests


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.request_calls = 0
        self.request_kwargs = []
        self.mounts = []
        self.cookies = requests.cookies.RequestsCookieJar()

    def mount(self, prefix, adapter):
        self.mounts.append((prefix, adapter))

    def request(self, **kwargs):
        self.request_calls += 1
        self.request_kwargs.append(kwargs)
        if self.responses:
            response = self.responses.pop(0)
            if isinstance(response, requests.RequestException):
                raise response
            return response
        return _json_response(200, {"ok": True})


class FailingSession:
    def request(self, **kwargs):
        raise requests.ConnectionError(
            "connection failed for https://provider.invalid?key=secret-provider-key"
        )


class FailingStreamResponse:
    status_code = 200

    def __init__(self):
        self.headers = {}
        self.closed = False

    def iter_lines(self, decode_unicode=True):
        raise RuntimeError("stream failed with secret-provider-key")

    def close(self):
        self.closed = True


class TrackingResponse(requests.Response):
    def __init__(self):
        super().__init__()
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        super().close()


def _json_response(status_code, payload):
    response = TrackingResponse()
    response.status_code = status_code
    response._content = json.dumps(payload).encode("utf-8")
    response.raw = Mock()
    response.headers["Content-Type"] = "application/json"
    return response


class TransportResilienceTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        os.environ["ADMIN_API_KEY"] = "admin-test-key"
        os.environ["FLASK_SECRET_KEY"] = "flask-test-secret"
        os.environ["JWT_SECRET"] = "jwt-test-secret"
        sys.modules.pop("services.proxy_service", None)
        self.proxy_module = importlib.import_module("services.proxy_service")
        self.proxy_module.ProxyService._sessions = {}
        self.proxy_module.ResilienceService.reset()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_make_base_request_reuses_provider_session_pool(self):
        fake_session = FakeSession([
            _json_response(200, {"ok": True}),
            _json_response(200, {"ok": True}),
        ])

        with patch("services.proxy_service.requests.Session", return_value=fake_session) as session_ctor:
            for _ in range(2):
                response = self.proxy_module.ProxyService._make_base_request(
                    method="GET",
                    url="https://example.invalid/v1/models",
                    headers={},
                    params={},
                    data=None,
                    api_provider="openai",
                    use_cache=False,
                )
                self.assertEqual(response.status_code, 200)

        self.assertEqual(session_ctor.call_count, 1)
        self.assertEqual(fake_session.request_calls, 2)
        self.assertEqual(len(fake_session.mounts), 2)

    def test_prepare_headers_canonicalizes_allowed_request_headers(self):
        headers = self.proxy_module.ProxyService.prepare_headers(
            {
                "content-type": "application/json",
                "accept": "text/event-stream",
                "http-referer": "https://client.example",
                "x-title": "Client App",
                "x-goog-user-project": "billing-project",
                "authorization": "Bearer user-key",
            },
            "openrouter",
            "provider-key",
        )

        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Accept"], "text/event-stream")
        self.assertEqual(headers["HTTP-Referer"], "https://client.example")
        self.assertEqual(headers["X-Title"], "Client App")
        self.assertEqual(headers["Authorization"], "Bearer provider-key")
        self.assertNotIn("content-type", headers)
        self.assertNotIn("authorization", headers)
        self.assertNotIn("X-Goog-User-Project", headers)

    def test_prepare_headers_allows_google_user_project_header(self):
        headers = self.proxy_module.ProxyService.prepare_headers(
            {"x-goog-user-project": "billing-project"},
            "gemini",
            "provider-key",
        )

        self.assertEqual(headers["X-Goog-User-Project"], "billing-project")

    def test_post_retryable_status_without_idempotency_key_is_not_retried(self):
        fake_session = FakeSession([
            _json_response(503, {"error": "temporary"}),
            _json_response(200, {"ok": True}),
        ])

        with patch("services.proxy_service.requests.Session", return_value=fake_session):
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://example.invalid/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                params={},
                data=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode("utf-8"),
                api_provider="openai",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(fake_session.request_calls, 1)

    def test_post_retryable_status_with_idempotency_key_is_retried(self):
        fake_session = FakeSession([
            _json_response(503, {"error": "temporary"}),
            _json_response(200, {"ok": True}),
        ])

        with patch("services.proxy_service.requests.Session", return_value=fake_session):
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://example.invalid/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Idempotency-Key": "req_123",
                },
                params={},
                data=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode("utf-8"),
                api_provider="openai",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(fake_session.request_calls, 2)

    def test_retry_closes_response_and_preserves_timeout_override(self):
        retry_response = _json_response(503, {"error": "temporary"})
        fake_session = FakeSession([
            retry_response,
            _json_response(200, {"ok": True}),
        ])

        with (
            patch("services.proxy_service.requests.Session", return_value=fake_session),
            patch("services.proxy_service.time.sleep"),
        ):
            response = self.proxy_module.ProxyService._make_base_request(
                method="GET",
                url="https://example.invalid/v1/models",
                headers={},
                params={},
                data=None,
                api_provider="openai",
                use_cache=False,
                timeout_override=(1, 2),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(retry_response.close_calls, 1)
        self.assertEqual(
            [call["timeout"] for call in fake_session.request_kwargs],
            [(1, 2), (1, 2)],
        )

    def test_timeout_payload_retry_closes_consumed_response(self):
        retry_response = _json_response(
            400,
            {"error": {"message": "timeout", "code": 400}},
        )
        fake_session = FakeSession([
            retry_response,
            _json_response(200, {"ok": True}),
        ])

        with (
            patch("services.proxy_service.requests.Session", return_value=fake_session),
            patch("services.proxy_service.time.sleep"),
        ):
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://example.invalid/v1/chat/completions",
                headers={"Idempotency-Key": "req_123"},
                params={},
                data=b"{}",
                api_provider="opencode",
                use_cache=False,
                timeout_override=(1, 2),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(retry_response.close_calls, 1)
        self.assertEqual(
            [call["timeout"] for call in fake_session.request_kwargs],
            [(1, 2), (1, 2)],
        )

    def test_make_request_forwards_timeout_override_to_managed_transport(self):
        fake_session = FakeSession([_json_response(200, {"ok": True})])

        with patch("services.proxy_service.requests.Session", return_value=fake_session):
            response = self.proxy_module.ProxyService.make_request(
                method="GET",
                url="https://example.invalid/v1/models",
                headers={},
                params={},
                data=None,
                api_provider="openai",
                use_cache=False,
                timeout_override=(2, 4),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(fake_session.request_kwargs[0]["timeout"], (2, 4))

    def test_exception_retry_preserves_timeout_override(self):
        fake_session = FakeSession([
            requests.ConnectTimeout("connect timed out"),
            _json_response(200, {"ok": True}),
        ])

        with (
            patch("services.proxy_service.requests.Session", return_value=fake_session),
            patch("services.proxy_service.time.sleep"),
        ):
            response = self.proxy_module.ProxyService._make_base_request(
                method="GET",
                url="https://example.invalid/v1/models",
                headers={},
                params={},
                data=None,
                api_provider="openai",
                use_cache=False,
                timeout_override=(2, 4),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [call["timeout"] for call in fake_session.request_kwargs],
            [(2, 4), (2, 4)],
        )

    def test_circuit_breaker_opens_after_failure_threshold(self):
        os.environ["CIRCUIT_BREAKER_FAILURES"] = "1"
        os.environ["CIRCUIT_BREAKER_COOLDOWN_SECONDS"] = "60"
        fake_session = FakeSession([_json_response(503, {"error": "temporary"})])

        with patch("services.proxy_service.requests.Session", return_value=fake_session):
            first = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://example.invalid/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                params={},
                data=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode("utf-8"),
                api_provider="openai",
                use_cache=False,
            )
            second = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://example.invalid/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                params={},
                data=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode("utf-8"),
                api_provider="openai",
                use_cache=False,
            )

        self.assertEqual(first.status_code, 503)
        self.assertEqual(second.status_code, 503)
        self.assertEqual(second.json()["error"]["type"], "circuit_open")
        self.assertEqual(fake_session.request_calls, 1)

    def test_transport_failures_do_not_reflect_upstream_exception_details(self):
        with patch.object(
            self.proxy_module.ProxyService,
            "_get_provider_session",
            return_value=FailingSession(),
        ):
            response = self.proxy_module.ProxyService._make_base_request(
                method="POST",
                url="https://provider.invalid/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                params={},
                data=b"{}",
                api_provider="openai",
                use_cache=False,
            )

        self.assertEqual(response.status_code, 502)
        payload = response.json()
        self.assertEqual(payload["error"]["type"], "upstream_transport_error")
        self.assertNotIn("secret-provider-key", response.text)
        self.assertNotIn("provider.invalid", response.text)

    def test_stream_failures_emit_opaque_sse_error(self):
        chunks = "".join(
            self.proxy_module.ProxyService._create_streaming_response(
                FailingStreamResponse(),
                "openai",
            )
        )

        self.assertIn(self.proxy_module.STREAM_FAILURE_MESSAGE, chunks)
        self.assertNotIn("secret-provider-key", chunks)

    def test_gemini_authentication_errors_do_not_reflect_upstream_body(self):
        upstream = _json_response(
            401,
            {"error": {"message": "credential secret-provider-key was rejected"}},
        )

        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=upstream,
        ):
            response = self.proxy_module.ProxyService._handle_gemini_request(
                method="POST",
                url=(
                    "https://generativelanguage.googleapis.com/v1beta/"
                    "chat/completions"
                ),
                headers={},
                params={"key": "AIza-provider-key"},
                data=b"{}",
                request_data={
                    "model": "gemini-2.0-flash",
                    "messages": [{"role": "user", "content": "hello"}],
                },
                use_cache=False,
                api_provider="gemini",
            )

        self.assertEqual(response.status_code, 401)
        self.assertNotIn("secret-provider-key", response.text)
        self.assertIn("configured provider credential was rejected", response.text)
        self.assertEqual(upstream.close_calls, 1)

    def test_openrouter_authentication_errors_do_not_reflect_upstream_body(self):
        upstream = _json_response(
            401,
            {"error": {"message": "credential secret-provider-key was rejected"}},
        )

        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=upstream,
        ):
            response = self.proxy_module.ProxyService._handle_openrouter_request(
                method="POST",
                url="https://openrouter.ai/api/v1/chat/completions",
                headers={},
                params={},
                data=b"{}",
                request_data={},
                use_cache=False,
                auth_token="provider-key",
            )

        self.assertEqual(response.status_code, 401)
        self.assertNotIn("secret-provider-key", response.text)
        self.assertIn("configured provider credential was rejected", response.text)
        self.assertEqual(upstream.close_calls, 1)

    def test_provider_stream_handlers_emit_opaque_errors(self):
        gemini_upstream = FailingStreamResponse()
        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=gemini_upstream,
        ):
            gemini_response = self.proxy_module.ProxyService._handle_gemini_request(
                method="POST",
                url=(
                    "https://generativelanguage.googleapis.com/v1beta/"
                    "chat/completions"
                ),
                headers={},
                params={"key": "AIza-provider-key"},
                data=b"{}",
                request_data={
                    "model": "gemini-2.0-flash",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
                use_cache=False,
                api_provider="gemini",
            )

        openrouter_upstream = FailingStreamResponse()
        with patch.object(
            self.proxy_module.ProxyService,
            "_make_base_request",
            return_value=openrouter_upstream,
        ):
            openrouter_response = (
                self.proxy_module.ProxyService._handle_openrouter_request(
                    method="POST",
                    url="https://openrouter.ai/api/v1/chat/completions",
                    headers={},
                    params={},
                    data=b"{}",
                    request_data={"stream": True},
                    use_cache=False,
                    auth_token="provider-key",
                )
            )

        for response in (gemini_response, openrouter_response):
            chunks = "".join(response.response)
            self.assertIn(self.proxy_module.STREAM_FAILURE_MESSAGE, chunks)
            self.assertNotIn("secret-provider-key", chunks)
        self.assertTrue(gemini_upstream.closed)
        self.assertTrue(openrouter_upstream.closed)

if __name__ == "__main__":
    unittest.main()
