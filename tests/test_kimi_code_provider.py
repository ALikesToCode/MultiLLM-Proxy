import os
import tempfile
import unittest
from unittest.mock import patch

from config import Config
from providers.registry import get_adapter
from services.auth_service import AuthService
from services.model_registry import ModelRegistry
from services.rate_limit_service import RateLimitService


class KimiCodeProviderRegistrationTest(unittest.TestCase):
    def test_kimi_code_uses_official_coding_base_url_and_long_timeout(self):
        self.assertEqual(
            Config.API_BASE_URLS["kimi-code"],
            "https://api.kimi.com/coding/v1",
        )
        self.assertEqual(Config.API_TIMEOUTS["kimi-code"], (5, 600))

    def test_kimi_code_adapter_uses_chat_path_without_duplicate_v1(self):
        adapter = get_adapter("kimi-code", Config.API_BASE_URLS)

        self.assertIsNotNone(adapter)
        self.assertEqual(
            adapter.chat_completions_url(),
            "https://api.kimi.com/coding/v1/chat/completions",
        )
        capabilities = adapter.capabilities()
        self.assertTrue(capabilities.supports_chat)
        self.assertTrue(capabilities.supports_streaming)
        self.assertTrue(capabilities.supports_tools)
        self.assertFalse(capabilities.supports_vision)
        self.assertFalse(capabilities.supports_embeddings)
        self.assertFalse(capabilities.supports_audio)
        self.assertFalse(capabilities.supports_images)
        self.assertFalse(capabilities.supports_json_schema)

    def test_kimi_code_loads_only_its_scoped_api_key(self):
        with patch.object(AuthService, "_api_keys", {}):
            with patch.dict(
                os.environ,
                {
                    "KIMI_CODE_API_KEY": "scoped-kimi-code-key",
                    "OPENAI_API_KEY": "unrelated-openai-key",
                },
                clear=False,
            ):
                AuthService._load_provider_api_keys()

                self.assertEqual(
                    AuthService.get_api_key("kimi-code"),
                    "scoped-kimi-code-key",
                )
                self.assertEqual(
                    AuthService._api_keys["kimi-code"],
                    "scoped-kimi-code-key",
                )

    def test_kimi_code_catalog_lists_only_documented_k3_model(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry_path = os.path.join(temp_dir, "models.sqlite3")
            with patch.dict(
                os.environ,
                {"MODEL_REGISTRY_DB_PATH": registry_path},
                clear=False,
            ):
                model = ModelRegistry.get_model(
                    "kimi-code:k3",
                    Config.API_BASE_URLS,
                )
                unknown_model = ModelRegistry.get_model(
                    "kimi-code:not-documented",
                    Config.API_BASE_URLS,
                )
                listed_model_ids = {
                    item.id for item in ModelRegistry.list_models(Config.API_BASE_URLS)
                }

        self.assertIsNotNone(model)
        self.assertEqual(model.provider, "kimi-code")
        self.assertEqual(model.display_name, "k3")
        self.assertTrue(model.supports_tools)
        self.assertIsNone(unknown_model)
        self.assertIn("kimi-code:k3", listed_model_ids)

    def test_hyphenated_provider_uses_shell_safe_rate_limit_prefix(self):
        with patch.dict(
            os.environ,
            {
                "KIMI_CODE_RATE_LIMIT_RPM": "7",
                "KIMI-CODE_RATE_LIMIT_RPM": "9",
                "RATE_LIMIT_RPM": "13",
            },
            clear=False,
        ):
            self.assertEqual(
                RateLimitService._provider_limit(
                    "kimi-code",
                    "RATE_LIMIT_RPM",
                    60,
                ),
                7,
            )


if __name__ == "__main__":
    unittest.main()
