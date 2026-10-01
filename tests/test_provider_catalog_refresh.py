import json
import threading
from unittest.mock import patch

import requests

from tests.test_cline_pass_provider import RECOMMENDED_MODELS
from tests.unified_api_test_case import UnifiedApiTestCase

FETCH = "services.provider_capability_discovery.fetch_public_capabilities"


class ProviderCatalogAutoRefreshTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        from services.provider_catalog_refresh import ProviderCatalogAutoRefresh

        self.now = 1000
        self.refresher = ProviderCatalogAutoRefresh(
            clock=lambda: self.now, ttl_seconds=1800, retry_seconds=300
        )
        self.app.extensions["provider_catalog_refresh"] = self.refresher
        self.app.config["PROVIDER_CATALOG_AUTO_REFRESH"] = True
        # models.dev is not part of these tests.
        enrichment = patch(FETCH, side_effect=ValueError("offline"))
        enrichment.start()
        self.addCleanup(enrichment.stop)
        self.requested_urls = []

    @staticmethod
    def _response(payload, status=200):
        response = requests.Response()
        response.status_code = status
        response._content = json.dumps(payload).encode()
        response._content_consumed = True
        response.headers["Content-Type"] = "application/json"
        return response

    def _upstream(self, **kwargs):
        url = kwargs["url"]
        self.requested_urls.append(url)
        if url == "https://api.cline.bot/api/v1/ai/cline/recommended-models":
            return self._response(RECOMMENDED_MODELS)
        if url == "https://openrouter.ai/api/v1/models":
            return self._response({"data": [{"id": "vendor/new-model-2026"}]})
        return self._response({}, status=503)

    def _models(self, path="/v1/models", field="data"):
        response = self.client.get(path, headers={"Authorization": "Bearer admin-test-key"})
        self.assertEqual(response.status_code, 200)
        return {model["id"]: model for model in response.json[field]}

    def _finish_refresh(self):
        thread = self.refresher._thread
        if thread is not None:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())

    def test_first_global_list_shows_every_providers_live_models(self):
        with patch.object(
            self.app_module.ProxyService, "make_request", side_effect=self._upstream
        ):
            models = self._models()
            self._finish_refresh()

        for model_id in (
            "cline-pass:cline-pass/glm-5.3",
            "cline-pass:cline-pass/qwen3.8-max",
            "cline-pass:cline-free/deepseek-v4.1-flash",
            "openrouter:vendor/new-model-2026",
        ):
            self.assertIn(model_id, models)
            self.assertIn("live", models[model_id]["sources"])
        self.assertNotIn("cline-pass:cline-cloud/kimi-k3", models)
        self.assertNotIn("cline-pass:anthropic/claude-sonnet-5.5", models)

    def test_documentation_search_lists_the_refreshed_models(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_admin-te",
                "scopes": ["admin"],
            }
        with patch.object(
            self.app_module.ProxyService, "make_request", side_effect=self._upstream
        ):
            response = self.client.get("/docs.json")
            self._finish_refresh()

        self.assertEqual(response.status_code, 200)
        model_ids = {model["id"] for model in response.json["models"]}
        self.assertIn("cline-pass:cline-pass/glm-5.3", model_ids)
        self.assertIn("openrouter:vendor/new-model-2026", model_ids)
        providers = {provider["id"]: provider for provider in response.json["providers"]}
        self.assertEqual(providers["cline-pass"]["name"], "ClinePass")

    def test_catalogs_refresh_again_only_after_the_refresh_interval(self):
        with patch.object(
            self.app_module.ProxyService, "make_request", side_effect=self._upstream
        ):
            self._models()
            self._finish_refresh()
            first = len(self.requested_urls)
            self.assertGreater(first, 0)

            self.now += 60
            self._models()
            self._finish_refresh()
            self.assertEqual(len(self.requested_urls), first)

            self.now += 1800
            self._models()
            self._finish_refresh()
        self.assertIn(
            "https://api.cline.bot/api/v1/ai/cline/recommended-models",
            self.requested_urls[first:],
        )

    def test_a_failed_catalog_keeps_the_last_good_models(self):
        responses = iter([RECOMMENDED_MODELS])

        def upstream(**kwargs):
            if "api.cline.bot" not in kwargs["url"]:
                return self._response({}, status=503)
            payload = next(responses, None)
            return self._response(payload or {}, status=200 if payload else 502)

        with patch.object(self.app_module.ProxyService, "make_request", side_effect=upstream):
            self._models()
            self._finish_refresh()
            self.now += 1800
            self._models()
            self._finish_refresh()
            models = self._models()

        self.assertIn("live", models["cline-pass:cline-pass/glm-5.3"]["sources"])

    def test_reads_do_not_wait_once_the_first_refresh_finished(self):
        release = threading.Event()

        def slow_upstream(**kwargs):
            release.wait(timeout=10)
            return self._upstream(**kwargs)

        with patch.object(
            self.app_module.ProxyService, "make_request", side_effect=self._upstream
        ):
            self._models()
            self._finish_refresh()
        self.now += 1800
        with patch.object(
            self.app_module.ProxyService, "make_request", side_effect=slow_upstream
        ):
            models = self._models()
            # The stale-but-good catalog is served while the refresh is still running.
            self.assertTrue(self.refresher._thread.is_alive())
            release.set()
            self._finish_refresh()
        self.assertIn("cline-pass:cline-pass/glm-5.3", models)

    def test_disabled_auto_refresh_makes_no_catalog_requests(self):
        self.app.config["PROVIDER_CATALOG_AUTO_REFRESH"] = False
        with patch.object(self.app_module.ProxyService, "make_request") as transport:
            models = self._models()
        transport.assert_not_called()
        self.assertIn("cline-pass:cline-pass/glm-5.3", models)
        self.assertEqual(models["cline-pass:cline-pass/glm-5.3"]["sources"], ["built-in"])
