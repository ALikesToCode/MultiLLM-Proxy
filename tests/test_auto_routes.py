import os
from unittest.mock import patch

import requests

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
