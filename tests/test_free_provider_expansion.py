import json
from unittest.mock import patch

from flask import Response

from services.free_provider_catalog import FREE_PROVIDERS, free_chat_url
from services.free_quota_service import FreeQuotaService
from tests.test_free_routes import catalog_row
from tests.unified_api_test_case import UnifiedApiTestCase


class FreeProviderExpansionTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config.update(
            FREE_ROUTE_EXTRA_PROVIDERS="",
            FREE_ROUTE_WORKERSAI_ACCOUNT_ID="",
            FREE_ROUTE_FREE_TIER_PROVIDERS="",
            FREE_ROUTE_PROVIDER_ORDER="",
        )
        self.rows = [catalog_row("opencode", "mimo-v2.5-free", vision=True)]
        catalog = patch(
            "services.free_model_policy.build_model_catalog",
            side_effect=lambda _: self.rows,
        )
        catalog.start()
        self.addCleanup(catalog.stop)
        self.keys = {"opencode": "test-opencode"}
        auth = patch.object(
            self.app_module.AuthService, "get_api_key", side_effect=self.keys.get
        )
        auth.start()
        self.addCleanup(auth.stop)
        self.headers = {
            "Authorization": "Bearer admin-test-key",
            "Origin": "https://example.test",
        }

    def post(self, payload=None, mode="text"):
        return self.client.post(
            f"/v1/free/{mode}/chat/completions",
            headers=self.headers,
            json=payload or {"messages": [{"role": "user", "content": "Hello"}]},
        )

    def enable(self, provider):
        self.keys.clear()
        self.keys[provider] = f"test-{provider}"
        self.rows = []
        self.app.config.update(
            FREE_ROUTE_EXTRA_PROVIDERS=provider,
            FREE_ROUTE_FREE_TIER_PROVIDERS=provider,
            FREE_ROUTE_WORKERSAI_ACCOUNT_ID="a" * 32,
        )

    def test_extra_keys_do_not_enable_new_destinations(self):
        self.keys.update(
            {name: "test-extra" for name, spec in FREE_PROVIDERS.items() if spec.extra}
        )
        self.app.config["FREE_ROUTE_FREE_TIER_PROVIDERS"] = "mistral,workersai,llm7"
        self.app.config["FREE_ROUTE_PROVIDER_ORDER"] = "mistral,zai,bazaarlink"
        with patch(
            "app.ProxyService.make_request", return_value=self._chat_response()
        ) as send:
            response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(send.call_args.kwargs["api_provider"], "opencode")

    def test_each_new_provider_uses_reviewed_model_origin_and_server_key(self):
        for name, spec in FREE_PROVIDERS.items():
            if not spec.extra:
                continue
            with self.subTest(provider=name):
                self.enable(name)
                with patch(
                    "app.ProxyService.make_request", return_value=self._chat_response()
                ) as send:
                    response = self.post()
                self.assertEqual(response.status_code, 200)
                args = send.call_args.kwargs
                self.assertEqual(args["url"], spec.chat_url.format(account_id="a" * 32))
                self.assertEqual(
                    args["headers"]["Authorization"], f"Bearer test-{name}"
                )
                self.assertEqual(json.loads(args["data"])["model"], spec.models[0][0])
                self.assertTrue(args["force_raw_passthrough"])

    def test_account_tiers_remain_blocked_until_confirmed(self):
        for name in ("mistral", "workersai", "llm7"):
            with self.subTest(provider=name):
                self.enable(name)
                self.app.config["FREE_ROUTE_FREE_TIER_PROVIDERS"] = ""
                with patch("app.ProxyService.make_request") as send:
                    response = self.post()
                self.assertEqual(response.status_code, 503)
                send.assert_not_called()

    def test_unreviewed_models_never_join_extra_providers(self):
        self.enable("zai")
        self.rows = [catalog_row("zai", "glm-5.3-free", vision=True)]
        with patch(
            "app.ProxyService.make_request", return_value=self._chat_response()
        ) as send:
            self.post()
        self.assertEqual(
            json.loads(send.call_args.kwargs["data"])["model"], "glm-4.5-flash"
        )

    def test_paid_price_on_seed_fails_closed(self):
        self.enable("zai")
        self.rows = [catalog_row("zai", "glm-4.5-flash", pricing={"prompt": "1"})]
        with patch("app.ProxyService.make_request") as send:
            response = self.post()
        self.assertEqual(response.status_code, 503)
        send.assert_not_called()

    def test_disabled_seed_remains_disabled(self):
        self.enable("orcarouter")
        self.rows = [catalog_row("orcarouter", "orcarouter/free", status="disabled")]
        with patch("app.ProxyService.make_request") as send:
            self.assertEqual(self.post().status_code, 503)
        send.assert_not_called()

    def test_vision_uses_only_reviewed_vision_seeds(self):
        image = {
            "type": "image_url",
            "image_url": {"url": "https://example.test/chart.png"},
        }
        payload = {"messages": [{"role": "user", "content": [image]}]}
        for name in ("mistral", "workersai", "zai", "orcarouter", "bazaarlink", "llm7"):
            with self.subTest(provider=name):
                self.enable(name)
                with patch(
                    "app.ProxyService.make_request", return_value=self._chat_response()
                ) as send:
                    response = self.post(payload, mode="vision")
                if name in {"mistral", "workersai"}:
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(
                        json.loads(send.call_args.kwargs["data"])["messages"],
                        payload["messages"],
                    )
                else:
                    self.assertEqual(response.status_code, 503)
                    send.assert_not_called()

    def test_bazaarlink_cannot_enable_paid_spillover_via_caller_header(self):
        self.enable("bazaarlink")
        self.keys["openrouter"] = "test-openrouter"
        self.app.config["FREE_ROUTE_PROVIDER_ORDER"] = "bazaarlink,openrouter"
        self.headers["X-Free-Fallback"] = "true"
        with patch(
            "app.ProxyService.make_request",
            side_effect=[Response(status=429), self._chat_response()],
        ) as send:
            response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            send.call_args_list[0].kwargs["headers"]["X-Free-Fallback"], "false"
        )
        self.assertNotIn("X-Free-Fallback", send.call_args_list[1].kwargs["headers"])
        self.assertEqual(
            response.headers["X-MultiLLM-Auto-Selected-Model"],
            "openrouter:openrouter/free",
        )

    def test_orcarouter_prompt_cap_does_not_cool_the_account(self):
        self.enable("orcarouter")
        with patch(
            "app.ProxyService.make_request",
            side_effect=[Response(status=429), self._chat_response()],
        ) as send:
            self.assertEqual(self.post().status_code, 503)
            self.assertEqual(self.post().status_code, 200)
        self.assertEqual(send.call_count, 2)
        self.assertEqual(FreeQuotaService.remaining("provider:orcarouter"), 0)

    def test_orcarouter_rate_window_does_cool_the_account(self):
        self.enable("orcarouter")
        with patch(
            "app.ProxyService.make_request",
            return_value=Response(status=429, headers={"Retry-After": "120"}),
        ):
            self.assertEqual(self.post().status_code, 429)
        self.assertGreater(FreeQuotaService.remaining("provider:orcarouter"), 115)

    def test_retired_model_fails_over_without_cooling_the_provider(self):
        self.enable("zai")
        self.keys["openrouter"] = "test-openrouter"
        self.app.config["FREE_ROUTE_PROVIDER_ORDER"] = "zai,openrouter"
        with patch(
            "app.ProxyService.make_request",
            side_effect=[Response(status=410), self._chat_response()],
        ):
            response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Provider"], "openrouter")
        self.assertEqual(FreeQuotaService.remaining("provider:zai"), 0)
        self.assertGreater(FreeQuotaService.remaining("model:zai:glm-4.5-flash"), 295)

    def test_invalid_cloudflare_account_cannot_change_destination(self):
        self.enable("workersai")
        for value in (
            "",
            "../other",
            "https://evil.test",
            "a" * 31,
            "g" * 32,
            "a" * 32 + "/ai",
        ):
            with self.subTest(account=value):
                self.app.config["FREE_ROUTE_WORKERSAI_ACCOUNT_ID"] = value
                self.assertIsNone(free_chat_url(self.app.config, "workersai"))
                with patch("app.ProxyService.make_request") as send:
                    self.assertEqual(self.post().status_code, 503)
                send.assert_not_called()

    def test_provider_setup_shows_missing_settings_not_values(self):
        self.enable("workersai")
        response = self.client.get("/v1/free/providers", headers=self.headers)
        rows = {r["id"]: r for r in response.get_json()["data"]}
        self.assertEqual(len(rows), 11)
        self.assertTrue(rows["workersai"]["ready"])
        self.assertEqual(rows["workersai"]["api_key_env_names"], ["WORKERSAI_API_KEY"])
        self.assertEqual(
            rows["workersai"]["account_id_setting"], "FREE_ROUTE_WORKERSAI_ACCOUNT_ID"
        )
        self.assertIn("provider_not_enabled", rows["mistral"]["missing"])
        self.assertIn("free_tier_not_confirmed", rows["mistral"]["missing"])
        self.assertIn("api_key_missing", rows["mistral"]["missing"])
        self.assertNotIn("test-workersai", response.get_data(as_text=True))
        self.assertNotIn("a" * 32, response.get_data(as_text=True))
        self.assertEqual(self.client.get("/v1/free/providers").status_code, 401)
