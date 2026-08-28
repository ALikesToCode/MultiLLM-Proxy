import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

from error_handlers import APIError


class FailingStreamResponse:
    status_code = 200

    def __init__(self):
        self.headers = {"content-type": "text/event-stream"}
        self.closed = False

    def iter_lines(self, decode_unicode=True):
        raise RuntimeError("stream failed with secret-provider-key")

    def close(self):
        self.closed = True


class ProxyErrorSafetyTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env_patch = patch.dict(
            os.environ,
            {
                "ADMIN_USERNAME": "admin",
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "AUTH_DB_PATH": os.path.join(self.tempdir.name, "auth.sqlite3"),
                "OPENAI_API_KEY": "openai-provider-key",
            },
            clear=False,
        )
        self.env_patch.start()
        for module_name in list(sys.modules):
            if module_name == "app" or module_name.startswith("routes."):
                sys.modules.pop(module_name, None)
        for module_name in (
            "route_helpers",
            "services.auth_service",
            "services.proxy_service",
        ):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.client = self.app_module.create_app().test_client()

    def tearDown(self):
        self.env_patch.stop()
        self.tempdir.cleanup()

    @property
    def auth_headers(self):
        return {"Authorization": "Bearer admin-test-key"}

    def test_generic_stream_does_not_reflect_transport_exception(self):
        upstream = FailingStreamResponse()
        with patch("app.ProxyService.make_request", return_value=upstream):
            response = self.client.post(
                "/openai/v1/chat/completions",
                headers=self.auth_headers,
                json={
                    "model": "gpt-test",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
            )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Upstream stream terminated unexpectedly.", body)
        self.assertNotIn("secret-provider-key", body)
        self.assertTrue(upstream.closed)

    def test_google_stream_error_does_not_reflect_upstream_body(self):
        upstream = requests.Response()
        upstream.status_code = 502
        upstream._content = json.dumps(
            {"error": "backend failed with secret-provider-key"}
        ).encode("utf-8")
        upstream.headers["Content-Type"] = "application/json"

        with (
            patch("app.AuthService.get_google_token", return_value="google-token"),
            patch("app.ProxyService.make_request", return_value=upstream),
        ):
            response = self.client.post(
                "/googleai/chat/completions",
                headers=self.auth_headers,
                json={
                    "model": "google-test",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
            )

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 502)
        self.assertIn("Upstream stream terminated unexpectedly.", body)
        self.assertNotIn("secret-provider-key", body)

    def test_google_internal_error_is_opaque(self):
        with (
            patch("app.AuthService.get_google_token", return_value="google-token"),
            patch(
                "app.ProxyService.make_request",
                side_effect=RuntimeError("failed with secret-provider-key"),
            ),
        ):
            response = self.client.post(
                "/googleai/chat/completions",
                headers=self.auth_headers,
                json={
                    "messages": [{"role": "user", "content": "hello"}],
                },
            )

        self.assertEqual(response.status_code, 500)
        payload = response.get_json()
        self.assertEqual(payload["message"], "An unexpected error occurred.")
        self.assertNotIn("secret-provider-key", response.get_data(as_text=True))

    def test_google_chat_rejects_json_arrays(self):
        response = self.client.post(
            "/googleai/chat/completions",
            headers=self.auth_headers,
            json=[],
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["message"],
            "Request body must be a JSON object",
        )

    def test_generic_provider_route_rejects_json_arrays(self):
        with patch("app.ProxyService.make_request") as make_request:
            response = self.client.post(
                "/openai/v1/chat/completions",
                headers=self.auth_headers,
                json=[],
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["message"],
            "Request body must be a JSON object",
        )
        make_request.assert_not_called()

    def test_together_processing_errors_do_not_reach_logs_or_exceptions(self):
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = b"{}"
        upstream.headers["Content-Type"] = "application/json"
        upstream.json = Mock(
            side_effect=RuntimeError("failed with secret-provider-key")
        )

        with (
            patch.object(
                self.app_module.ProxyService,
                "_make_base_request",
                return_value=upstream,
            ),
            self.assertLogs("services.proxy_service", level="ERROR") as captured,
            self.assertRaises(APIError) as raised,
        ):
            self.app_module.ProxyService._handle_together_request(
                "POST",
                "https://api.together.xyz/v1/chat/completions",
                {},
                {},
                b"{}",
                {"model": "test-model"},
            )

        self.assertEqual(raised.exception.message, "Together AI response processing failed")
        self.assertNotIn("secret-provider-key", "\n".join(captured.output))

    def test_together_success_does_not_log_request_or_response_payloads(self):
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = json.dumps(
            {
                "choices": [{"message": {"content": "model reply"}}],
                "diagnostic": "response-payload-secret",
            }
        ).encode("utf-8")
        upstream.headers["Content-Type"] = "application/json"

        with (
            patch.object(
                self.app_module.ProxyService,
                "_make_base_request",
                return_value=upstream,
            ),
            self.assertLogs("services.proxy_service", level="INFO") as captured,
        ):
            response = self.app_module.ProxyService._handle_together_request(
                "POST",
                "https://api.together.xyz/v1/chat/completions",
                {"X-Debug": "request-header-secret"},
                {"trace": "request-query-secret"},
                b"{}",
                {
                    "model": "test-model",
                    "metadata": {"tenant": "request-payload-secret"},
                },
            )

        self.assertIs(response, upstream)
        log_output = "\n".join(captured.output)
        for secret in (
            "request-header-secret",
            "request-query-secret",
            "request-payload-secret",
            "response-payload-secret",
        ):
            self.assertNotIn(secret, log_output)

    def test_google_route_does_not_log_request_metadata_or_response_headers(self):
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = b'{"choices": []}'
        upstream.headers.update(
            {
                "Content-Type": "application/json",
                "X-Debug": "response-header-secret",
            }
        )

        with (
            patch("app.AuthService.get_google_token", return_value="google-token"),
            patch("app.ProxyService.make_request", return_value=upstream),
            self.assertLogs("routes.proxy", level="DEBUG") as captured,
        ):
            response = self.client.post(
                "/googleai/chat/completions",
                headers=self.auth_headers,
                json={
                    "messages": [{"role": "user", "content": "hello"}],
                    "extra_body": {"metadata": "request-metadata-secret"},
                },
            )

        self.assertEqual(response.status_code, 200)
        log_output = "\n".join(captured.output)
        self.assertNotIn("request-metadata-secret", log_output)
        self.assertNotIn("response-header-secret", log_output)

    def test_groq_processing_errors_do_not_reach_logs_or_exceptions(self):
        with (
            patch.object(
                self.app_module.ProxyService,
                "_make_base_request",
                side_effect=RuntimeError("failed with secret-provider-key"),
            ),
            self.assertLogs("services.proxy_service", level="ERROR") as captured,
            self.assertRaises(APIError) as raised,
        ):
            self.app_module.ProxyService._handle_groq_request(
                "POST",
                "https://api.groq.com/openai/v1/chat/completions",
                {},
                {},
                b"{}",
                {"model": "test-model", "messages": [{"role": "user"}]},
            )

        self.assertEqual(raised.exception.message, "Groq request handling failed")
        self.assertNotIn("secret-provider-key", "\n".join(captured.output))

    def test_stream_standardizer_does_not_reflect_unexpected_objects(self):
        secret_chunk = Mock()
        secret_chunk.decode.return_value = secret_chunk
        secret_chunk.strip.side_effect = RuntimeError("secret-provider-key")

        with self.assertLogs("services.proxy_service", level="ERROR") as captured:
            payload = self.app_module.ProxyService._standardize_streaming_chunk(
                secret_chunk,
                "test-provider",
            )

        self.assertIn("Upstream stream terminated unexpectedly.", payload)
        self.assertNotIn("secret-provider-key", payload)
        self.assertNotIn("secret-provider-key", "\n".join(captured.output))

    def test_nineteen_stream_failure_is_opaque_and_closes_response(self):
        upstream = FailingStreamResponse()
        model = "TheBloke/Rogue-Rose-103b-v0.2-AWQ"

        with patch.object(
            self.app_module.ProxyService,
            "_make_base_request",
            return_value=upstream,
        ):
            response = self.app_module.ProxyService._handle_rogue_rose_request(
                "POST",
                "https://api.nineteen.ai/v1/chat/completions",
                {},
                {},
                b"{}",
                {
                    "model": model,
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
            )
            body = response.get_data(as_text=True)

        self.assertIn("Upstream stream terminated unexpectedly.", body)
        self.assertNotIn("secret-provider-key", body)
        self.assertTrue(upstream.closed)


if __name__ == "__main__":
    unittest.main()
