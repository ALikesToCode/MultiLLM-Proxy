import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import Config
from providers.registry import get_adapter
from services.auth_service import AuthService
from services.model_registry import ModelRegistry
from services.rate_limit_service import RateLimitService


class CodexEasyProviderRegistrationTest(unittest.TestCase):
    def test_codex_easy_uses_official_base_url_and_long_running_timeout(self):
        self.assertEqual(Config.API_BASE_URLS["codex-easy"], "https://codex-easy.ai")
        self.assertEqual(Config.API_TIMEOUTS["codex-easy"], (5, 600))

    def test_codex_easy_adapter_exposes_conservative_openai_capabilities(self):
        adapter = get_adapter("codex-easy", Config.API_BASE_URLS)

        self.assertIsNotNone(adapter)
        self.assertEqual(
            adapter.chat_completions_url(),
            "https://codex-easy.ai/v1/chat/completions",
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

    def test_codex_easy_scoped_key_is_preferred_over_existing_alias(self):
        with patch.object(AuthService, "_api_keys", {}):
            with patch.dict(
                os.environ,
                {
                    "CODEX_EASY_API_KEY": "scoped-codex-easy-key",
                    "CODEX_API_KEY": "existing-codex-key",
                },
                clear=False,
            ):
                AuthService._load_provider_api_keys()

                self.assertEqual(
                    AuthService.get_api_key("codex-easy"),
                    "scoped-codex-easy-key",
                )
                self.assertEqual(
                    AuthService._api_keys["codex-easy"],
                    "scoped-codex-easy-key",
                )

    def test_existing_codex_key_name_remains_a_supported_fallback(self):
        with patch.object(AuthService, "_api_keys", {}):
            with patch.dict(
                os.environ,
                {
                    "CODEX_EASY_API_KEY": "",
                    "CODEX_API_KEY": "existing-codex-key",
                },
                clear=False,
            ):
                AuthService._load_provider_api_keys()

                self.assertEqual(
                    AuthService.get_api_key("codex-easy"),
                    "existing-codex-key",
                )
                self.assertEqual(
                    AuthService._api_keys["codex-easy"],
                    "existing-codex-key",
                )

    def test_codex_easy_accepts_key_scoped_models_without_guessing_catalog(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            registry_path = os.path.join(temp_dir, "models.sqlite3")
            with patch.dict(
                os.environ,
                {"MODEL_REGISTRY_DB_PATH": registry_path},
                clear=False,
            ):
                model = ModelRegistry.get_model(
                    "codex-easy:model-from-key-scoped-catalog",
                    Config.API_BASE_URLS,
                )
                listed_model_ids = {
                    item.id for item in ModelRegistry.list_models(Config.API_BASE_URLS)
                }

        self.assertIsNotNone(model)
        self.assertEqual(model.provider, "codex-easy")
        self.assertEqual(model.display_name, "model-from-key-scoped-catalog")
        self.assertNotIn(
            "codex-easy:model-from-key-scoped-catalog",
            listed_model_ids,
        )

    def test_example_environment_documents_scoped_key_and_alias(self):
        env_example = (
            Path(__file__).resolve().parents[1] / ".env.example"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "CODEX_EASY_API_KEY=your-codex-easy-api-key",
            env_example,
        )
        self.assertIn(
            "# Optional compatibility alias: CODEX_API_KEY=your-codex-easy-api-key",
            env_example,
        )

    def test_hyphenated_provider_uses_shell_safe_rate_limit_prefix(self):
        with patch.dict(
            os.environ,
            {
                "CODEX_EASY_RATE_LIMIT_RPM": "7",
                "CODEX-EASY_RATE_LIMIT_RPM": "9",
                "OPENAI_RATE_LIMIT_RPM": "11",
                "RATE_LIMIT_RPM": "13",
            },
            clear=False,
        ):
            self.assertEqual(
                RateLimitService._provider_limit(
                    "codex-easy",
                    "RATE_LIMIT_RPM",
                    60,
                ),
                7,
            )
            self.assertEqual(
                RateLimitService._provider_limit(
                    "openai",
                    "RATE_LIMIT_RPM",
                    60,
                ),
                11,
            )


if __name__ == "__main__":
    unittest.main()
