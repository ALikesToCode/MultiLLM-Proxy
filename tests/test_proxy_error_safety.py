import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests


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


if __name__ == "__main__":
    unittest.main()
