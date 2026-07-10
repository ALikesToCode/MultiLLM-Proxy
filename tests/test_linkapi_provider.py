import os
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from providers.registry import get_adapter
from services.auth_service import AuthService
from services.model_registry import ModelRegistry


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
        self.assertFalse(capabilities.supports_vision)
        self.assertFalse(capabilities.supports_embeddings)
        self.assertFalse(capabilities.supports_audio)
        self.assertFalse(capabilities.supports_images)
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


if __name__ == "__main__":
    unittest.main()
