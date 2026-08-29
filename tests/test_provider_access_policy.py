import importlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests

from services.provider_access_policy import provider_route_scope
from services.rate_limit_service import LimitDecision


class ProviderRouteScopeTest(unittest.TestCase):
    def test_documented_generation_and_catalog_routes_use_narrow_scopes(self):
        self.assertEqual(
            provider_route_scope("openai", "v1/chat/completions", "POST"),
            "chat",
        )
        self.assertEqual(
            provider_route_scope("openrouter", "models", "GET"),
            "models",
        )
        self.assertEqual(
            provider_route_scope(
                "gemini",
                "models/gemini-3.6-flash:generateContent",
                "POST",
            ),
            "chat",
        )

    def test_raw_unknown_and_state_changing_routes_require_admin(self):
        cases = (
            ("linkapi", "v1/chat/completions", "POST"),
            ("openai", "v1/organization/admin_api_keys", "GET"),
            ("openai", "v1/chat/completions", "DELETE"),
            ("openai", "v1/files", "POST"),
        )
        for provider, path, method in cases:
            with self.subTest(provider=provider, path=path, method=method):
                self.assertEqual(
                    provider_route_scope(provider, path, method),
                    "admin",
                )


class ProviderRouteScopeIntegrationTest(unittest.TestCase):
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
                "OPENROUTER_API_KEY": "openrouter-provider-key",
                "LINKAPI_API_KEY": "linkapi-provider-key",
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

    @staticmethod
    def _user(scopes):
        return {
            "username": "scoped-user",
            "api_key_prefix": "mllm_scope",
            "scopes": scopes,
        }

    def test_chat_key_cannot_reach_provider_account_api(self):
        with (
            patch.object(
                self.app_module.AuthService,
                "verify_api_key",
                return_value=self._user(["chat"]),
            ),
            patch.object(self.app_module.ProxyService, "make_request") as make_request,
        ):
            response = self.client.get(
                "/openai/v1/organization/admin_api_keys",
                headers={"Authorization": "Bearer user-key"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "insufficient_scope")
        make_request.assert_not_called()

    def test_chat_key_cannot_use_raw_server_credentials(self):
        with (
            patch.object(
                self.app_module.AuthService,
                "verify_api_key",
                return_value=self._user(["chat"]),
            ),
            patch.object(self.app_module.ProxyService, "make_request") as make_request,
        ):
            response = self.client.post(
                "/linkapi/v1/chat/completions",
                headers={"Authorization": "Bearer user-key"},
                json={"messages": [{"role": "user", "content": "hello"}]},
            )

        self.assertEqual(response.status_code, 403)
        make_request.assert_not_called()

    def test_scoped_generation_and_catalog_requests_still_dispatch(self):
        upstream = requests.Response()
        upstream.status_code = 200
        upstream._content = b'{"data": []}'
        upstream.headers["Content-Type"] = "application/json"
        allowed = LimitDecision(True, metadata={})

        cases = (
            ("POST", "/openai/v1/chat/completions", ["chat"]),
            ("GET", "/openrouter/models", ["models"]),
        )
        for method, path, scopes in cases:
            with (
                self.subTest(method=method, path=path),
                patch.object(
                    self.app_module.AuthService,
                    "verify_api_key",
                    return_value=self._user(scopes),
                ),
                patch("route_helpers.RateLimitService.enforce_request", return_value=allowed),
                patch.object(
                    self.app_module.ProxyService,
                    "make_request",
                    return_value=upstream,
                ) as make_request,
            ):
                response = self.client.open(
                    path,
                    method=method,
                    headers={"Authorization": "Bearer user-key"},
                    json={"messages": [{"role": "user", "content": "hello"}]}
                    if method == "POST"
                    else None,
                )

            self.assertEqual(response.status_code, 200)
            make_request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
