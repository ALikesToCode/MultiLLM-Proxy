import importlib
import json
import os
import sys
import unittest
from unittest.mock import patch

import requests


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.request_calls = 0
        self.mounts = []

    def mount(self, prefix, adapter):
        self.mounts.append((prefix, adapter))

    def request(self, **kwargs):
        self.request_calls += 1
        if self.responses:
            return self.responses.pop(0)
        return _json_response(200, {"ok": True})


def _json_response(status_code, payload):
    response = requests.Response()
    response.status_code = status_code
    response._content = json.dumps(payload).encode("utf-8")
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
        self.proxy_module.ProxyService._circuit_breakers = {}

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


if __name__ == "__main__":
    unittest.main()
