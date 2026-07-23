import os
import tempfile
import unittest
from unittest.mock import patch

from werkzeug.datastructures import MultiDict

from config import Config
from providers.registry import get_adapter
from services.auth_service import AuthService
from services.model_registry import ModelRegistry
from services.proxy_service import ProxyService


class LinkAPIProviderRegistrationTest(unittest.TestCase):
    def test_linkapi_uses_official_base_url_and_long_running_timeout(self):
        self.assertEqual(Config.API_BASE_URLS["linkapi"], "https://api.linkapi.ai")
        self.assertEqual(Config.API_TIMEOUTS["linkapi"], (5, 600))

    def test_linkapi_adapter_exposes_openai_compatible_chat_metadata(self):
        adapter = get_adapter("linkapi", Config.API_BASE_URLS)

        self.assertIsNotNone(adapter)
        self.assertEqual(
            adapter.chat_completions_url(),
            "https://api.linkapi.ai/v1/chat/completions",
        )
        capabilities = adapter.capabilities()
        self.assertTrue(capabilities.supports_chat)
        self.assertTrue(capabilities.supports_streaming)
        self.assertFalse(capabilities.supports_tools)
        self.assertTrue(capabilities.supports_vision)
        self.assertFalse(capabilities.supports_embeddings)
        self.assertFalse(capabilities.supports_audio)
        self.assertTrue(capabilities.supports_images)
        self.assertFalse(capabilities.supports_json_schema)

    def test_linkapi_key_alias_is_loaded_and_preferred(self):
        with patch.object(AuthService, "_api_keys", {}):
            with patch.dict(
                os.environ,
                {
                    "LINKAPI_KEY": "linkapi-short-name-key",
                    "LINKAPI_API_KEY": "linkapi-canonical-key",
                },
                clear=False,
            ):
                AuthService._load_provider_api_keys()

                self.assertEqual(
                    AuthService.get_api_key("linkapi"),
                    "linkapi-short-name-key",
                )
                self.assertEqual(
                    AuthService._api_keys["linkapi"],
                    "linkapi-short-name-key",
                )

    def test_linkapi_api_key_name_remains_a_supported_fallback(self):
        with patch.object(AuthService, "_api_keys", {}):
            with patch.dict(
                os.environ,
                {
                    "LINKAPI_KEY": "",
                    "LINKAPI_API_KEY": "linkapi-canonical-key",
                },
                clear=False,
            ):
                AuthService._load_provider_api_keys()

                self.assertEqual(
                    AuthService.get_api_key("linkapi"),
                    "linkapi-canonical-key",
                )
                self.assertEqual(
                    AuthService._api_keys["linkapi"],
                    "linkapi-canonical-key",
                )

    def test_linkapi_accepts_live_catalog_model_names_without_guessing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry_path = os.path.join(temp_dir, "models.sqlite3")
            with patch.dict(
                os.environ,
                {"MODEL_REGISTRY_DB_PATH": registry_path},
                clear=False,
            ):
                model = ModelRegistry.get_model(
                    "linkapi:provider/model-not-yet-known-locally",
                    Config.API_BASE_URLS,
                )
                listed_model_ids = {
                    item.id for item in ModelRegistry.list_models(Config.API_BASE_URLS)
                }

        self.assertIsNotNone(model)
        self.assertEqual(model.provider, "linkapi")
        self.assertEqual(
            model.display_name,
            "provider/model-not-yet-known-locally",
        )
        self.assertNotIn(
            "linkapi:provider/model-not-yet-known-locally",
            listed_model_ids,
        )


class LinkAPINativeTransportPreparationTest(unittest.TestCase):
    def test_claude_messages_uses_native_key_and_version_headers(self):
        headers = ProxyService.prepare_headers(
            {
                "Authorization": "Bearer downstream-proxy-key",
                "X-Api-Key": "downstream-proxy-key",
                "Anthropic-Beta": "prompt-caching-2024-07-31",
            },
            "linkapi",
            "upstream-linkapi-key",
            upstream_path="v1/messages",
        )

        self.assertEqual(headers["X-Api-Key"], "upstream-linkapi-key")
        self.assertEqual(headers["Anthropic-Version"], "2023-06-01")
        self.assertEqual(headers["Anthropic-Beta"], "prompt-caching-2024-07-31")
        self.assertNotIn("Authorization", headers)

    def test_openai_routes_use_bearer_auth_and_forward_idempotency(self):
        headers = ProxyService.prepare_headers(
            {
                "X-Api-Key": "downstream-proxy-key",
                "Idempotency-Key": "request-123",
                "OpenAI-Beta": "responses=v1",
            },
            "linkapi",
            "upstream-linkapi-key",
            upstream_path="/v1/responses",
        )

        self.assertEqual(headers["Authorization"], "Bearer upstream-linkapi-key")
        self.assertEqual(headers["Idempotency-Key"], "request-123")
        self.assertEqual(headers["OpenAI-Beta"], "responses=v1")
        self.assertNotIn("X-Api-Key", headers)

    def test_openai_image_generation_uses_bearer_auth(self):
        headers = ProxyService.prepare_headers(
            {
                "Authorization": "Bearer downstream-proxy-key",
                "Content-Type": "application/json",
                "Idempotency-Key": "image-request-123",
            },
            "linkapi",
            "upstream-linkapi-key",
            upstream_path="/v1/images/generations",
        )

        self.assertEqual(headers["Authorization"], "Bearer upstream-linkapi-key")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Idempotency-Key"], "image-request-123")
        self.assertNotIn("X-Api-Key", headers)
        self.assertNotIn("X-Goog-Api-Key", headers)

    def test_gemini_query_key_is_stripped_and_upstream_header_is_replaced(self):
        params = ProxyService.prepare_params(
            MultiDict(
                [
                    ("alt", "sse"),
                    ("alt", "json"),
                    ("key", "downstream-proxy-key"),
                ]
            ),
            "linkapi",
            "upstream-linkapi-key",
            upstream_path="v1beta/models/gemini-test:streamGenerateContent",
        )
        headers = ProxyService.prepare_headers(
            {
                "X-Goog-Api-Key": "downstream-proxy-key",
                "X-Goog-Api-Client": "gl-python/3.12",
            },
            "linkapi",
            "upstream-linkapi-key",
            upstream_path="v1beta/models/gemini-test:streamGenerateContent",
        )

        self.assertEqual(
            params,
            [
                ("alt", "sse"),
                ("alt", "json"),
            ],
        )
        self.assertEqual(headers["X-Goog-Api-Client"], "gl-python/3.12")
        self.assertEqual(headers["X-Goog-Api-Key"], "upstream-linkapi-key")
        self.assertNotIn("Authorization", headers)

    def test_gemini_model_listing_uses_header_auth_too(self):
        params = ProxyService.prepare_params(
            MultiDict([("key", "downstream-proxy-key")]),
            "linkapi",
            "upstream-linkapi-key",
            upstream_path="v1beta/models",
        )
        headers = ProxyService.prepare_headers(
            {},
            "linkapi",
            "upstream-linkapi-key",
            upstream_path="v1beta/models",
        )

        self.assertEqual(params, [])
        self.assertEqual(headers["X-Goog-Api-Key"], "upstream-linkapi-key")
        self.assertNotIn("Authorization", headers)

    def test_all_v1beta_resources_use_gemini_header_auth(self):
        for upstream_path in (
            "v1beta",
            "/v1beta/cachedContents",
            "v1beta/fileSearchStores",
        ):
            with self.subTest(upstream_path=upstream_path):
                params = ProxyService.prepare_params(
                    MultiDict(
                        [
                            ("pageSize", "10"),
                            ("key", "downstream-proxy-key"),
                        ]
                    ),
                    "linkapi",
                    "upstream-linkapi-key",
                    upstream_path=upstream_path,
                )
                headers = ProxyService.prepare_headers(
                    {"X-Goog-Api-Key": "downstream-proxy-key"},
                    "linkapi",
                    "upstream-linkapi-key",
                    upstream_path=upstream_path,
                )

                self.assertEqual(params, [("pageSize", "10")])
                self.assertEqual(headers["X-Goog-Api-Key"], "upstream-linkapi-key")
                self.assertNotIn("Authorization", headers)


if __name__ == "__main__":
    unittest.main()
