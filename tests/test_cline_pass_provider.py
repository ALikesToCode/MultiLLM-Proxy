import os
import unittest
from unittest.mock import patch

from config import Config
from providers.registry import get_adapter
from services.auth_primitives import provider_api_key_env_names
from services.auth_service import AuthService
from services.model_registry import ModelRegistry
from services.provider_catalog_service import (
    PROVIDER_CATALOG_SPECS,
    ProviderCatalogService,
)
from services.rate_limit_service import RateLimitService

RECOMMENDED_MODELS = {
    "recommended": [
        {"id": "anthropic/claude-sonnet-5.5", "name": "claude-sonnet-5.5"},
    ],
    "free": [
        {
            "id": "cline-free/deepseek-v4.1-flash",
            "name": "Deepseek-v4.1-Flash",
            "description": "Fast and efficient with 1M context window",
        },
    ],
    "clinePass": [
        {"id": "cline-pass/glm-5.3", "name": "cline-pass/glm-5.3"},
        {"id": "cline-pass/qwen3.8-max", "name": "cline-pass/qwen3.8-max"},
        "not-an-entry",
    ],
    "clineCloud": [
        {"id": "cline-cloud/kimi-k3", "name": "cline-cloud/kimi-k3"},
    ],
}


class ClinePassProviderTest(unittest.TestCase):
    def test_chat_goes_to_the_cline_api_with_a_long_timeout(self):
        adapter = get_adapter("cline-pass", Config.API_BASE_URLS)

        self.assertIsNotNone(adapter)
        self.assertEqual(
            adapter.chat_completions_url(),
            "https://api.cline.bot/api/v1/chat/completions",
        )
        self.assertTrue(adapter.capabilities().supports_tools)
        self.assertEqual(Config.API_TIMEOUTS["cline-pass"], (5, 600))

    def test_the_cline_api_key_is_the_provider_credential(self):
        self.assertEqual(
            provider_api_key_env_names("cline-pass"),
            ("CLINE_API_KEY", "CLINE_PASS_API_KEY"),
        )
        with patch.object(AuthService, "_api_keys", {}):
            with patch.dict(os.environ, {"CLINE_API_KEY": "cline-test-key"}):
                AuthService._load_provider_api_keys()
                self.assertEqual(AuthService.get_api_key("cline-pass"), "cline-test-key")

    def test_built_in_models_list_cline_pass_before_the_first_refresh(self):
        model = ModelRegistry.get_model("cline-pass:cline-pass/glm-5.3", Config.API_BASE_URLS)

        self.assertIsNotNone(model)
        self.assertEqual(model.provider, "cline-pass")

    def test_catalog_keeps_the_subscription_and_free_models_only(self):
        models = ProviderCatalogService.extract_model_ids("cline-pass", RECOMMENDED_MODELS)

        self.assertEqual(
            models,
            (
                "cline-free/deepseek-v4.1-flash",
                "cline-pass/glm-5.3",
                "cline-pass/qwen3.8-max",
            ),
        )

    def test_catalog_reads_the_public_recommended_models_document_without_a_key(self):
        spec = PROVIDER_CATALOG_SPECS["cline-pass"]

        self.assertEqual(spec.upstream_path, "ai/cline/recommended-models")
        self.assertEqual(
            ProviderCatalogService._credential_candidates(AuthService, "cline-pass"),
            (None,),
        )

    def test_agent_sized_requests_fit_the_default_limits(self):
        self.assertEqual(
            RateLimitService._provider_limit("cline-pass", "MAX_PROMPT_TOKENS", 1),
            1_048_576,
        )
        self.assertEqual(
            RateLimitService._provider_limit("cline-pass", "MAX_REQUEST_BYTES", 1),
            16 * 1024 * 1024,
        )


if __name__ == "__main__":
    unittest.main()
