import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests


class UnifiedApiRouteTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "OPENCODE_API_KEY": "opencode-provider-key",
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
        self.config_module = importlib.import_module("config")
        self.original_gemini_models = list(self.config_module.Config.GEMINI_MODELS)
        self.config_module.Config.GEMINI_MODELS = ["gemini-test-model"]
        self.app = self.app_module.create_app()
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def tearDown(self):
        self.config_module.Config.GEMINI_MODELS = self.original_gemini_models
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    @staticmethod
    def _chat_response(text="ok"):
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(
            {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [
                    {
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"total_tokens": 3},
            }
        ).encode("utf-8")
        response.headers["Content-Type"] = "application/json"
        return response

    def test_v1_models_lists_provider_prefixed_models(self):
        response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )

        self.assertEqual(response.status_code, 200)
        model_ids = {model["id"] for model in response.get_json()["data"]}
        self.assertIn("opencode:kimi-k2.5", model_ids)
        self.assertIn("gemini:gemini-test-model", model_ids)

    def test_v1_chat_completions_routes_provider_model(self):
        upstream_response = self._chat_response("hello")

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.5",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["choices"][0]["message"]["content"], "hello")
        request_kwargs = make_request.call_args.kwargs
        self.assertEqual(request_kwargs["api_provider"], "opencode")
        self.assertEqual(
            request_kwargs["url"],
            "https://opencode.ai/zen/go/v1/chat/completions",
        )
        upstream_payload = json.loads(request_kwargs["data"])
        self.assertEqual(upstream_payload["model"], "kimi-k2.5")
        self.assertEqual(
            request_kwargs["headers"]["Authorization"],
            "Bearer opencode-provider-key",
        )

    def test_v1_chat_model_resolution_does_not_list_entire_registry(self):
        upstream_response = self._chat_response("hello")

        with patch("app.ProxyService.make_request", return_value=upstream_response), patch(
            "routes.unified.ModelRegistry.list_models",
            side_effect=AssertionError("list_models should not run on chat request"),
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.5",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)

    def test_v1_chat_requires_provider_prefixed_model(self):
        response = self.client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer admin-test-key"},
            json={"model": "kimi-k2.5", "messages": []},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("provider:model", response.get_json()["message"])

    def test_admin_can_disable_model_and_v1_chat_blocks_it(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

        disable_response = self.client.post("/admin/models/opencode:kimi-k2.5/disable")
        self.assertEqual(disable_response.status_code, 200)
        self.assertEqual(disable_response.get_json()["status"], "disabled")

        response = self.client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer admin-test-key"},
            json={
                "model": "opencode:kimi-k2.5",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("disabled", response.get_json()["message"])

    def test_admin_disable_unknown_model_returns_404(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

        response = self.client.post(
            "/admin/models/opencode:not-a-model/disable",
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn("Model not found", response.get_json()["message"])

    def test_admin_model_disable_requires_csrf_when_enabled(self):
        self.app.config["WTF_CSRF_ENABLED"] = True
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

        response = self.client.post("/admin/models/opencode:kimi-k2.5/disable")

        self.assertEqual(response.status_code, 400)

    def test_v1_responses_bridges_to_chat_completions(self):
        upstream_response = self._chat_response("response text")

        with patch("app.ProxyService.make_request", return_value=upstream_response) as make_request:
            response = self.client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "opencode:kimi-k2.5",
                    "instructions": "Be brief",
                    "input": "Say hi",
                    "max_output_tokens": 12,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["object"], "response")
        self.assertEqual(payload["output_text"], "response text")

        upstream_payload = json.loads(make_request.call_args.kwargs["data"])
        self.assertEqual(upstream_payload["model"], "kimi-k2.5")
        self.assertEqual(upstream_payload["max_tokens"], 12)
        self.assertEqual(
            upstream_payload["messages"],
            [
                {"role": "system", "content": "Be brief"},
                {"role": "user", "content": "Say hi"},
            ],
        )

    def test_v1_responses_treats_non_json_upstream_as_provider_failure(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 502
        upstream_response._content = b"<html>bad gateway</html>"
        upstream_response.headers["Content-Type"] = "text/html"

        with patch("app.ProxyService.make_request", return_value=upstream_response):
            response = self.client.post(
                "/v1/responses",
                headers={
                    "Authorization": "Bearer admin-test-key",
                    "Accept": "application/json",
                },
                json={
                    "model": "opencode:kimi-k2.5",
                    "input": "Say hi",
                },
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["error"], "internal_error")


if __name__ == "__main__":
    unittest.main()
