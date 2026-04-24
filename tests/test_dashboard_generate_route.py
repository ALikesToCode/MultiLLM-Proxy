import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests


class DashboardGenerateRouteTest(unittest.TestCase):
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
                "OPENROUTER_API_KEY": "openrouter-provider-key",
            },
            clear=False,
        )
        self.env_patch.start()

        for module_name in ("app", "services.auth_service", "routes.proxy"):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.flask_app = self.app_module.create_app()
        self.flask_app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.flask_app.test_client()
        self.app_module.MetricsService.get_instance().requests.clear()

    def tearDown(self):
        self.env_patch.stop()
        self.tempdir.cleanup()

    def _set_admin_session(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_admin",
                "scopes": ["admin", "chat"],
                "session_id": "test-session",
            }

    def test_dashboard_chat_generate_uses_proxy_service_make_request(self):
        self._set_admin_session()
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode("utf-8")
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/api/backends/chat-completions/generate",
                json={
                    "provider": "openrouter",
                    "model": "openai/gpt-4o-mini",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "ok")

        make_request.assert_called_once()
        call_kwargs = make_request.call_args.kwargs
        self.assertEqual(call_kwargs["url"], "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(call_kwargs["api_provider"], "openrouter")
        self.assertEqual(call_kwargs["headers"]["Authorization"], "Bearer openrouter-provider-key")
        self.assertNotIn("provider", json.loads(call_kwargs["data"]))

        metrics = list(self.app_module.MetricsService.get_instance().requests)
        self.assertTrue(
            any(
                item["provider"] == "openrouter" and item["status_code"] == 200
                for item in metrics
            )
        )

    def test_dashboard_chat_generate_requires_authenticated_json_user(self):
        response = self.client.post(
            "/api/backends/chat-completions/generate",
            json={"provider": "openrouter"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["message"], "Authentication required")

    def test_dashboard_chat_generate_returns_clean_400_for_bad_provider(self):
        self._set_admin_session()
        response = self.client.post(
            "/api/backends/chat-completions/generate",
            json={"provider": "not-real", "messages": []},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["message"], "Unsupported provider: not-real")

    def test_dashboard_chat_generate_does_not_leak_internal_proxy_errors(self):
        self._set_admin_session()
        with patch(
            "app.ProxyService.make_request",
            side_effect=TypeError("ProxyService.get_instance() takes 0 positional arguments"),
        ):
            response = self.client.post(
                "/api/backends/chat-completions/generate",
                json={
                    "provider": "openrouter",
                    "model": "openai/gpt-4o-mini",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )

        self.assertEqual(response.status_code, 502)
        response_text = response.get_data(as_text=True)
        self.assertNotIn("ProxyService.get_instance", response_text)
        self.assertNotIn("takes 0 positional arguments", response_text)
        self.assertEqual(response.get_json()["message"], "An unexpected error occurred.")


if __name__ == "__main__":
    unittest.main()
