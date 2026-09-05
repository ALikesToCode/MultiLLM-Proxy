from unittest.mock import patch

from services.provider_capability_discovery import PUBLIC_CAPABILITY_SOURCES
from services.provider_catalog_service import (
    ProviderCatalogModel,
    ProviderCatalogService,
)
from tests.test_provider_catalog_service import _FakeProxyService
from tests.unified_api_test_case import UnifiedApiTestCase


class ModelVisionCatalogTest(UnifiedApiTestCase):
    def test_opencode_zen_free_models_are_enriched_after_catalog_merge(self):
        auth = type("Auth", (), {"get_api_key": staticmethod(lambda _: "fixture-key")})
        go = "https://opencode.ai/zen/go/v1"
        zen = "https://opencode.ai/zen/v1"
        with (
            patch.object(
                _FakeProxyService,
                "payloads_by_url",
                {
                    f"{go}/models": {
                        "data": [{"id": "go-fixture", "input_modalities": ["text"]}]
                    },
                    f"{zen}/models": {
                        "data": [{"id": "mimo-v2.5-free"}, {"id": "zen-paid-fixture"}]
                    },
                },
            ),
            patch(
                "services.provider_capability_discovery.fetch_public_capabilities",
                return_value={
                    "opencode": {
                        "models": {
                            "mimo-v2.5-free": {
                                "modalities": {"input": ["text", "image"]}
                            }
                        }
                    },
                },
            ) as fetch,
        ):
            results = ProviderCatalogService.refresh_configured(
                {"opencode": go},
                auth,
                _FakeProxyService,
                supplemental_base_urls={"opencode": zen},
            )
        self.assertEqual(results[0]["model_count"], 2)
        models = {
            model.model_id: model for model in ProviderCatalogService.list_models()
        }
        self.assertEqual(set(models), {"go-fixture", "mimo-v2.5-free"})
        self.assertEqual(
            models["mimo-v2.5-free"].metadata["input_modalities"], ["text", "image"]
        )
        fetch.assert_called_once_with("opencode")

    def _catalog_model(self, provider, model_id, metadata=None):
        ProviderCatalogService.replace_provider_models(
            provider,
            [ProviderCatalogModel(provider, model_id, "ignored", metadata=metadata)],
        )
        response = self.client.get(
            "/v1/models", headers={"Authorization": "Bearer admin-test-key"}
        )
        self.assertEqual(response.status_code, 200)
        return next(
            model
            for model in response.get_json()["data"]
            if model["id"] == f"{provider}:{model_id}"
        )

    def test_live_model_input_modalities_override_provider_default(self):
        for provider in ("aihubmix", "opencode"):
            with self.subTest(provider=provider):
                model = self._catalog_model(
                    provider,
                    "vision-fixture-free",
                    {"input_modalities": ["text", "image"]},
                )
                self.assertIs(model["capabilities"]["supports_vision"], True)

    def test_missing_model_metadata_is_unknown_not_text_only(self):
        model = self._catalog_model("aihubmix", "unknown-fixture-free")
        self.assertIsNone(model["capabilities"]["supports_vision"])
        self.assertIsNone(model["supports_vision"])

    def test_explicit_false_overrides_image_modalities(self):
        model = self._catalog_model(
            "aihubmix",
            "text-fixture-free",
            {"supports_vision": False, "input_modalities": ["image", "text"]},
        )
        self.assertIs(model["capabilities"]["supports_vision"], False)
        self.assertIs(model["supports_vision"], False)

    def test_null_placeholder_does_not_override_inferred_vision(self):
        model = self._catalog_model(
            "opencode",
            "vision-fixture-free",
            {"supports_vision": None, "modalities": {"input": ["image", "text"]}},
        )
        self.assertIs(model["capabilities"]["supports_vision"], True)
        self.assertIs(model["supports_vision"], True)

    def test_refresh_enriches_available_ids_before_unified_serialization(self):
        auth = type("Auth", (), {"get_api_key": staticmethod(lambda _: "fixture-key")})
        fixtures = (
            (
                "aihubmix",
                "https://aihubmix.com",
                "gemma-4-31b-it-free",
                {
                    "data": [
                        {
                            "model_id": "gemma-4-31b-it-free",
                            "input_modalities": "text,image",
                        },
                        {
                            "model_id": "not-advertised-free",
                            "input_modalities": "text,image",
                        },
                    ],
                },
            ),
            (
                "opencode",
                "https://opencode.ai/zen/go/v1",
                "mimo-v2.5-free",
                {
                    "opencode": {
                        "models": {
                            "mimo-v2.5-free": {
                                "modalities": {"input": ["text", "image"]}
                            },
                            "not-advertised-free": {"modalities": {"input": ["image"]}},
                        }
                    },
                },
            ),
        )
        for provider, base_url, model_id, public in fixtures:
            with (
                self.subTest(provider=provider),
                patch.object(
                    _FakeProxyService,
                    "payloads_by_url",
                    {
                        f"{base_url}/{'v1/' if provider == 'aihubmix' else ''}models": {
                            "data": [{"id": model_id}],
                        }
                    },
                ),
                patch(
                    "services.provider_capability_discovery.fetch_public_capabilities",
                    return_value=public,
                ) as fetch,
            ):
                results = ProviderCatalogService.refresh_configured(
                    {provider: base_url},
                    auth,
                    _FakeProxyService,
                )
                self.assertEqual(results[0]["status"], "updated")
                self.assertEqual(results[0]["model_count"], 1)
                fetch.assert_called_once_with(provider)
                response = self.client.get(
                    "/v1/models",
                    headers={"Authorization": "Bearer admin-test-key"},
                )
                catalog = {item["id"]: item for item in response.get_json()["data"]}
                model = catalog[f"{provider}:{model_id}"]
                self.assertIs(model["supports_vision"], True)
                self.assertIs(model["capabilities"]["supports_vision"], True)
                self.assertEqual(model["input_modalities"], ["text", "image"])
                self.assertEqual(
                    model["vision_metadata_source"], PUBLIC_CAPABILITY_SOURCES[provider]
                )
                self.assertNotIn(f"{provider}:not-advertised-free", catalog)
                fetch.assert_called_once_with(provider)
