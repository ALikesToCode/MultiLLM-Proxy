import importlib
import json
import os
import sys
import unittest
from unittest.mock import patch

import requests


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
                },
                json={
                    "model": "kimi-k2.5",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "max_tokens": 128,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "Hello from OpenCode")

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


if __name__ == "__main__":
    unittest.main()
