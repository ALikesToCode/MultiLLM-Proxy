import os
from unittest.mock import patch

import requests

from services.provider_catalog_service import ProviderCatalogService
from tests.unified_api_test_case import UnifiedApiTestCase


class AutoRouteTest(UnifiedApiTestCase):
    def _authenticate_admin(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

    def test_v1_models_lists_seeded_auto_route(self):
        response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )

        self.assertEqual(response.status_code, 200)
        model_ids = {model["id"] for model in response.get_json()["data"]}
        self.assertIn("auto:glm-5.2", model_ids)

    def test_auto_chat_skips_unconfigured_provider_and_uses_next_candidate(self):
        upstream_response = self._chat_response("open code selected")

        with patch(
            "app.ProxyService.make_request",
            return_value=upstream_response,
        ) as make_request, patch.object(
            self.app_module.AuthService,
            "get_api_keys",
            return_value=[],
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "auto:glm-5.2",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(make_request.call_count, 1)
        self.assertEqual(make_request.call_args.kwargs["api_provider"], "opencode")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Route"], "auto:glm-5.2")
        self.assertEqual(
            response.headers["X-MultiLLM-Auto-Selected-Model"],
            "opencode:glm-5.2",
        )
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "1")
        self.assertEqual(
            response.headers["X-MultiLLM-Route-Decision"],
            "auto-failover",
        )

    def test_auto_chat_advances_after_provider_rate_limit(self):
        os.environ["NANOGPT_API_KEY"] = "nano-provider-key"
        os.environ["NAVYAI_API_KEY"] = "navy-provider-key"
        rate_limited = requests.Response()
        rate_limited.status_code = 429
        rate_limited._content = b'{"error":{"message":"rate limited"}}'
        rate_limited.headers["Content-Type"] = "application/json"
        success = self._chat_response("open code fallback")

        with (
            patch(
                "routes.unified.NanoGPTKeyPool.select_key",
                return_value="nano-provider-key",
            ),
            patch(
                "app.ProxyService.make_request",
                side_effect=[rate_limited, success],
            ) as make_request,
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "auto:glm-5.2",
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": False,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [call.kwargs["api_provider"] for call in make_request.call_args_list],
            ["nanogpt", "opencode"],
        )
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
        self.assertEqual(
            response.headers["X-MultiLLM-Auto-Selected-Model"],
            "opencode:glm-5.2",
        )
        self.assertEqual(
            response.get_json()["choices"][0]["message"]["content"],
            "open code fallback",
        )

    def test_auto_chat_advances_after_provider_insufficient_balance(self):
        os.environ["NANOGPT_API_KEY"] = "nano-provider-key"
        insufficient_balance = requests.Response()
        insufficient_balance.status_code = 402
        insufficient_balance._content = (
            b'{"error":"Insufficient balance","code":"insufficient_balance",'
            b'"availableBalance":0,"requiredBalance":0.01054176}'
        )
        insufficient_balance.headers["Content-Type"] = "application/json"
        success = self._chat_response("open code balance fallback")

        with (
            patch(
                "routes.unified.NanoGPTKeyPool.select_key",
                return_value="nano-provider-key",
            ),
            patch(
                "app.ProxyService.make_request",
                side_effect=[insufficient_balance, success],
            ) as make_request,
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "auto:glm-5.2",
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [call.kwargs["api_provider"] for call in make_request.call_args_list],
            ["nanogpt", "opencode"],
        )
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "2")
        self.assertEqual(
            response.headers["X-MultiLLM-Auto-Selected-Model"],
            "opencode:glm-5.2",
        )
        self.assertEqual(
            response.get_json()["choices"][0]["message"]["content"],
            "open code balance fallback",
        )

    def test_auto_chat_does_not_replay_ambiguous_server_failure(self):
        os.environ["NANOGPT_API_KEY"] = "nano-provider-key"
        server_failure = requests.Response()
        server_failure.status_code = 503
        server_failure._content = b'{"error":{"message":"upstream unavailable"}}'
        server_failure.headers["Content-Type"] = "application/json"

        with (
            patch(
                "routes.unified.NanoGPTKeyPool.select_key",
                return_value="nano-provider-key",
            ),
            patch(
                "app.ProxyService.make_request",
                return_value=server_failure,
            ) as make_request,
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "auto:glm-5.2",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(make_request.call_count, 1)
        self.assertEqual(make_request.call_args.kwargs["api_provider"], "nanogpt")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "1")

    def test_unified_nanogpt_uses_key_pool_and_invalidates_rate_limited_key(self):
        os.environ["NANOGPT_API_KEY"] = "first-nano-key"
        os.environ["NANOGPT_API_KEY_1"] = "working-nano-key"
        rate_limited = requests.Response()
        rate_limited.status_code = 429
        rate_limited._content = b'{"error":{"message":"rate limited"}}'
        rate_limited.headers["Content-Type"] = "application/json"

        with (
            patch(
                "routes.unified.NanoGPTKeyPool.select_key",
                return_value="working-nano-key",
            ) as select_key,
            patch(
                "routes.unified.NanoGPTKeyPool.invalidate",
            ) as invalidate,
            patch(
                "app.ProxyService.make_request",
                return_value=rate_limited,
            ) as make_request,
        ):
            response = self.client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-test-key"},
                json={
                    "model": "nanogpt:glm-5.2",
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )

        self.assertEqual(response.status_code, 429)
        select_key.assert_called_once()
        self.assertEqual(
            make_request.call_args.kwargs["headers"]["Authorization"],
            "Bearer working-nano-key",
        )
        invalidate.assert_called_once()
        self.assertEqual(invalidate.call_args.args[:2], ("working-nano-key", 429))

    def test_admin_can_create_and_reorder_auto_route(self):
        self._authenticate_admin()

        response = self.client.put(
            "/admin/auto-routes",
            json={
                "route_id": "auto:kimi-k3",
                "candidates": [
                    "navyai:kimi-k3",
                    "opencode:kimi-k3",
                    "nanogpt:kimi-k3",
                ],
            },
        )

        self.assertEqual(response.status_code, 200)
        routes = {route["id"]: route for route in response.get_json()["routes"]}
        self.assertEqual(
            [item["model_id"] for item in routes["auto:kimi-k3"]["candidates"]],
            ["navyai:kimi-k3", "opencode:kimi-k3", "nanogpt:kimi-k3"],
        )

        models_response = self.client.get(
            "/v1/models",
            headers={"Authorization": "Bearer admin-test-key"},
        )
        model_ids = {model["id"] for model in models_response.get_json()["data"]}
        self.assertIn("auto:kimi-k3", model_ids)

    def test_admin_payload_combines_live_models_and_setup_metadata(self):
        self._authenticate_admin()
        ProviderCatalogService.replace_provider_models(
            "opencode",
            ("live-only-model",),
            discovered_at="2026-08-14T10:00:00+00:00",
        )

        response = self.client.get("/admin/auto-routes")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        models = {model["id"]: model for model in payload["model_catalog"]}
        providers = {provider["id"]: provider for provider in payload["providers"]}
        self.assertEqual(models["opencode:live-only-model"]["sources"], ["live"])
        self.assertIn("OPENCODE_GO_API_KEY", providers["opencode"]["credential_env"])
        self.assertEqual(
            providers["nanogpt"]["credential_env"][:3],
            ["NANOGPT_API_KEY", "NANOGPT_API_KEY_1", "NANOGPT_API_KEY_2"],
        )
        self.assertEqual(providers["opencode"]["catalog_path"], "/opencode/v1/models")
        self.assertEqual(
            providers["opencode"]["catalog_updated_at"],
            "2026-08-14T10:00:00+00:00",
        )

    def test_admin_can_refresh_configured_provider_catalogs(self):
        self._authenticate_admin()
        refresh_result = {
            "provider": "opencode",
            "status": "updated",
            "truncated": False,
            "model_count": 2,
        }

        with patch.object(
            ProviderCatalogService,
            "refresh_configured",
            return_value=[refresh_result],
        ) as refresh:
            response = self.client.post("/admin/auto-routes/catalog")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["catalog_refresh"], [refresh_result])
        refresh.assert_called_once_with(
            self.app.config["API_BASE_URLS"],
            self.app_module.AuthService,
            self.app_module.ProxyService,
        )

    def test_admin_auto_route_rejects_nested_or_duplicate_candidates(self):
        self._authenticate_admin()

        nested = self.client.put(
            "/admin/auto-routes",
            json={
                "route_id": "auto:nested",
                "candidates": ["auto:glm-5.2"],
            },
        )
        duplicate = self.client.put(
            "/admin/auto-routes",
            json={
                "route_id": "auto:duplicate",
                "candidates": ["opencode:glm-5.2", "opencode:glm-5.2"],
            },
        )

        self.assertEqual(nested.status_code, 400)
        self.assertIn("cannot contain", nested.get_json()["message"])
        self.assertEqual(duplicate.status_code, 400)
        self.assertIn("Duplicate", duplicate.get_json()["message"])
