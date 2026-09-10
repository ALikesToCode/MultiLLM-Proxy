import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import requests

from tests.unified_api_test_case import UnifiedApiTestCase


class ImageRelayCatalogTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config["IMAGE_RELAY_CATALOG_AUTO_REFRESH"] = True
        from services.image_relay_catalog import ImageRelayCatalogRefresh

        self.now = 1000
        self.app.extensions["image_relay_catalog_refresh"] = ImageRelayCatalogRefresh(
            clock=lambda: self.now,
        )
        self.keys = patch.object(
            self.app_module.AuthService,
            "get_api_keys",
            side_effect=lambda provider: (
                ["gguu-test-key"] if provider == "gguu" else []
            ),
        )
        self.keys.start()
        self.addCleanup(self.keys.stop)
        key = patch.object(
            self.app_module.AuthService,
            "get_api_key",
            side_effect=lambda provider: (
                "gguu-test-key" if provider == "gguu" else None
            ),
        )
        key.start()
        self.addCleanup(key.stop)
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_admin-te",
                "scopes": ["admin"],
            }

    @staticmethod
    def _catalog_response(status=200, data=None):
        response = requests.Response()
        response.status_code = status
        response._content = json.dumps(
            {
                "object": "list",
                "data": data
                if data is not None
                else [
                    {"id": "gpt-image-2", "type": "model"},
                    {"id": "gpt-image-2.5", "type": "model"},
                    {"id": "gpt-image-3.0", "type": "model"},
                    {"id": "text-test", "type": "model"},
                ],
            }
        ).encode()
        response._content_consumed = True
        response.headers["Content-Type"] = "application/json"
        return response

    def _get(self, path="/v1/models"):
        return self.client.get(path, headers={"Authorization": "Bearer admin-test-key"})

    def _assert_new_image_model(self, response, field):
        self.assertEqual(response.status_code, 200)
        models = {model["id"]: model for model in response.json[field]}
        self.assertTrue(
            "gguu:gpt-image-2.5" in models, "GGUU live model missing from catalog"
        )
        for model_id in ("gguu:gpt-image-2.5", "gguu:gpt-image-3.0"):
            self.assertTrue(models[model_id]["capabilities"]["supports_images"])
            self.assertEqual(models[model_id]["sources"], ["live"])
        self.assertFalse(models["gguu:text-test"]["capabilities"]["supports_images"])
        return models

    def test_global_list_discovers_new_image_models_on_first_read(self):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            return_value=self._catalog_response(),
        ) as transport:
            self._assert_new_image_model(self._get(), "data")
        transport.assert_called_once()
        self.assertEqual(transport.call_args.kwargs["method"], "GET")
        self.assertEqual(
            transport.call_args.kwargs["url"], "https://gguuai.com/v1/models"
        )

    def test_admin_model_list_uses_the_live_catalog(self):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            return_value=self._catalog_response(),
        ):
            models = self._assert_new_image_model(self._get("/admin/models"), "models")
        self.assertEqual(models["gguu:gpt-image-2.5"]["display_name"], "gpt-image-2.5")
        self.assertIn("input_cost_per_million", models["opencode:glm-5.2"])

    def test_operations_menu_discovers_models_without_manual_refresh(self):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            return_value=self._catalog_response(),
        ):
            response = self._get("/admin/auto-routes")
            self._assert_new_image_model(response, "model_catalog")
        gguu = next(
            provider
            for provider in response.json["providers"]
            if provider["id"] == "gguu"
        )
        self.assertIn("gpt-image-2.5", gguu["models"])
        self.assertIsNotNone(gguu["catalog_updated_at"])

    def test_documentation_menu_uses_the_same_catalog(self):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            return_value=self._catalog_response(),
        ):
            self._assert_new_image_model(self._get("/docs.json"), "models")

    def test_explicit_text_metadata_overrides_image_family_inference(self):
        from services.model_catalog_service import build_model_catalog
        from services.provider_catalog_service import ProviderCatalogService

        ProviderCatalogService.replace_provider_models(
            "gguu",
            ProviderCatalogService.extract_models(
                "gguu",
                {
                    "data": [
                        {"id": "gpt-image-2.5", "supports_image_output": False},
                        {"id": "gpt-image-3.0", "output_modalities": ["text"]},
                        {"id": "other-image-model", "output_modalities": ["image"]},
                    ]
                },
            ),
        )
        models = {
            model["id"]: model
            for model in build_model_catalog(self.app.config["API_BASE_URLS"])
        }
        self.assertFalse(
            models["gguu:gpt-image-2.5"]["capabilities"]["supports_images"]
        )
        self.assertFalse(
            models["gguu:gpt-image-3.0"]["capabilities"]["supports_images"]
        )
        self.assertTrue(
            models["gguu:other-image-model"]["capabilities"]["supports_images"]
        )

    def test_views_share_refresh_window_and_refresh_after_expiry(self):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            side_effect=lambda **kwargs: self._catalog_response(),
        ) as transport:
            for path in (
                "/v1/models",
                "/admin/models",
                "/admin/auto-routes",
                "/docs.json",
            ):
                self.assertEqual(self._get(path).status_code, 200)
            transport.assert_called_once()
            self.now += 299
            self._get()
            transport.assert_called_once()
            self.now += 1
            self._assert_new_image_model(self._get(), "data")
        self.assertEqual(transport.call_count, 2)

    def test_failed_refresh_retains_models_and_retries_after_cooldown(self):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            side_effect=[
                self._catalog_response(),
                self._catalog_response(status=503),
                self._catalog_response(),
            ],
        ) as transport:
            self._assert_new_image_model(self._get(), "data")
            self.now += 300
            self._assert_new_image_model(self._get(), "data")
            self.now += 59
            self._assert_new_image_model(self._get(), "data")
            self.assertEqual(transport.call_count, 2)
            self.now += 1
            self._assert_new_image_model(self._get(), "data")
        self.assertEqual(transport.call_count, 3)

    def test_empty_upstream_catalog_does_not_erase_last_good_models(self):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            side_effect=[
                self._catalog_response(),
                self._catalog_response(data=[]),
            ],
        ):
            self._get()
            self.now += 300
            self._assert_new_image_model(self._get(), "data")

    def test_cold_restart_rehydrates_an_empty_catalog(self):
        from services.image_relay_catalog import ImageRelayCatalogRefresh
        from services.provider_catalog_service import ProviderCatalogService

        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            side_effect=lambda **kwargs: self._catalog_response(),
        ) as transport:
            self._get()
            ProviderCatalogService.replace_provider_models("gguu", ())
            self.app.extensions["image_relay_catalog_refresh"] = (
                ImageRelayCatalogRefresh()
            )
            self._assert_new_image_model(self._get(), "data")
        self.assertEqual(transport.call_count, 2)

    def test_unconfigured_relays_do_not_make_catalog_requests(self):
        with (
            patch.object(self.app_module.AuthService, "get_api_key", return_value=None),
            patch.object(self.app_module.ProxyService, "make_request") as transport,
        ):
            self.assertEqual(self._get().status_code, 200)
        transport.assert_not_called()

    def test_concurrent_cold_reads_share_one_fetch_and_both_include_new_model(self):
        started = threading.Event()
        release = threading.Event()

        def fetch(**kwargs):
            started.set()
            if not release.wait(timeout=5):
                raise AssertionError("Catalog test did not release transport")
            return self._catalog_response()

        def read_catalog():
            with self.app.test_client() as client:
                return client.get(
                    "/v1/models", headers={"Authorization": "Bearer admin-test-key"}
                )

        with patch.object(
            self.app_module.ProxyService, "make_request", side_effect=fetch
        ) as transport:
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(read_catalog)
                try:
                    self.assertTrue(started.wait(timeout=5))
                    second = executor.submit(read_catalog)
                finally:
                    release.set()
                self._assert_new_image_model(first.result(timeout=5), "data")
                self._assert_new_image_model(second.result(timeout=5), "data")
        transport.assert_called_once()

    def test_discovered_model_can_be_selected_for_unified_image_generation(self):
        image_response = requests.Response()
        image_response.status_code = 200
        image_response._content = b'{"data":[{"b64_json":"aW1hZ2U="}]}'
        image_response._content_consumed = True
        image_response.headers["Content-Type"] = "application/json"
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            side_effect=[
                self._catalog_response(),
                image_response,
            ],
        ) as transport:
            self._get()
            response = self.client.post(
                "/v1/images/generations",
                headers={
                    "Authorization": "Bearer admin-test-key",
                },
                json={"model": "gguu:gpt-image-2.5", "prompt": "A blue square"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"data": [{"b64_json": "aW1hZ2U="}]})
        forwarded = transport.call_args.kwargs
        self.assertEqual(forwarded["url"], "https://gguuai.com/v1/images/generations")
        self.assertEqual(json.loads(forwarded["data"])["model"], "gpt-image-2.5")

    def test_disabled_live_models_stay_hidden_after_refresh(self):
        with patch.object(
            self.app_module.ProxyService,
            "make_request",
            side_effect=lambda **kwargs: self._catalog_response(),
        ):
            self._get()
            response = self.client.post("/admin/models/gguu:gpt-image-2.5/disable")
            self.assertEqual(response.status_code, 200)
            self.now += 300
            self.assertNotIn(
                "gguu:gpt-image-2.5",
                [model["id"] for model in self._get().json["data"]],
            )
            models = self._assert_new_image_model(self._get("/admin/models"), "models")
        self.assertEqual(models["gguu:gpt-image-2.5"]["status"], "disabled")

    def test_unauthenticated_catalog_request_does_not_fetch_upstream(self):
        with self.client.session_transaction() as session:
            session.clear()
        with patch.object(self.app_module.ProxyService, "make_request") as transport:
            self.assertEqual(self.client.get("/v1/models").status_code, 401)
            self.assertEqual(self.client.options("/v1/models").status_code, 204)
        transport.assert_not_called()
