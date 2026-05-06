import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests


class MimoProviderRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "MIMO_API_KEY": "mimo-provider-key",
                "ALLOWED_ORIGINS": "https://example.com",
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
        self.client = self.app_module.create_app().test_client()

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_mimo_chat_completions_routes_to_token_plan_sgp_endpoint(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = json.dumps(
            {
                "id": "chatcmpl-mimo",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello from MiMo"},
                        "finish_reason": "stop",
                    }
                ],
            }
        ).encode("utf-8")
        upstream_response.headers["Content-Type"] = "application/json"

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/mimo/chat/completions",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Content-Type": "application/json",
                    "Origin": "https://example.com",
                },
                json={
                    "model": "mimo-v2.5-pro",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "max_tokens": 128,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "Hello from MiMo")
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://example.com")

        make_request.assert_called_once()
        self.assertEqual(
            make_request.call_args.kwargs["url"],
            "https://token-plan-sgp.xiaomimimo.com/v1/chat/completions",
        )
        self.assertEqual(make_request.call_args.kwargs["api_provider"], "mimo")
        self.assertEqual(
            make_request.call_args.kwargs["headers"]["Authorization"],
            "Bearer mimo-provider-key",
        )


if __name__ == "__main__":
    unittest.main()
