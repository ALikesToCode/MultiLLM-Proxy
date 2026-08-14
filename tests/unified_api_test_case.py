import importlib
import json
import os
import sys
import tempfile
import unittest

import requests


class UnifiedApiTestCase(unittest.TestCase):
    """Isolated application fixture shared by unified API route tests."""

    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "OPENCODE_GO_API_KEY": "opencode-provider-key",
                "OPENCODE_API_KEY": "opencode-provider-key",
                "MIMO_API_KEY": "mimo-provider-key",
                "LINKAPI_KEY": "linkapi-provider-key",
                "CODEX_EASY_API_KEY": "codex-easy-provider-key",
                "AUTH_DB_PATH": os.path.join(self.temp_dir.name, "auth.sqlite3"),
                "RATE_LIMIT_DB_PATH": os.path.join(
                    self.temp_dir.name, "limits.sqlite3"
                ),
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
