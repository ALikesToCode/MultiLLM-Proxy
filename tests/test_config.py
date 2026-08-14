import importlib
import os
import sys
import types
import unittest
from unittest.mock import patch


class ConfigRuntimeEnvTest(unittest.TestCase):
    def test_config_loads_runtime_env_before_evaluating_class_values(self):
        fake_env_loader = types.ModuleType("env_loader")

        def load_runtime_env():
            os.environ["PROJECT_ID"] = "test-project"
            os.environ["LOCATION"] = "us-central1"
            os.environ["GOOGLE_ENDPOINT"] = "google.example.test"
            os.environ["SERVER_HOST"] = "127.0.0.1"
            os.environ["SERVER_PORT"] = "1555"
            os.environ["GROQ_API_KEY_2"] = "groq-second"
            os.environ["GROQ_API_KEY_1"] = "groq-first"
            os.environ["NANOGPT_BASE_URL"] = "https://cake.nano-gpt.com/api"
            os.environ["NANOGPT_BILLING_MODE"] = "subscription"
            os.environ["NANOGPT_SUBSCRIPTION_BASE_URL"] = (
                "https://cake.nano-gpt.com/api/subscription"
            )
            os.environ["NANOGPT_BATCH_BASE_URL"] = "https://batch.example.test/v1"
            os.environ["NANOGPT_ORIGIN_URL"] = "https://cake.nano-gpt.com"
            os.environ["NAVYAI_BASE_URL"] = "https://navy.example.test"
            os.environ["OPENCODE_GO_BASE_URL"] = "https://go.example.test/v1"

        fake_env_loader.load_runtime_env = load_runtime_env

        with patch.dict(os.environ, {}, clear=True):
            with patch.dict(sys.modules, {"env_loader": fake_env_loader}):
                sys.modules.pop("config", None)
                config_module = importlib.import_module("config")

        self.assertEqual(config_module.Config.PROJECT_ID, "test-project")
        self.assertEqual(config_module.Config.LOCATION, "us-central1")
        self.assertEqual(config_module.Config.ENDPOINT, "google.example.test")
        self.assertEqual(config_module.Config.SERVER_BASE_URL, "http://127.0.0.1:1555")
        self.assertEqual(
            config_module.Config.API_BASE_URLS["googleai"],
            "https://google.example.test/v1/projects/test-project/locations/us-central1/endpoints/openapi",
        )
        self.assertEqual(config_module.Config.GROQ_API_KEYS, ["groq-first", "groq-second"])
        self.assertEqual(
            config_module.Config.API_BASE_URLS["nanogpt"],
            "https://cake.nano-gpt.com/api/subscription",
        )
        self.assertEqual(config_module.Config.NANOGPT_BILLING_MODE, "subscription")
        self.assertEqual(
            config_module.Config.NANOGPT_STANDARD_BASE_URL,
            "https://cake.nano-gpt.com/api",
        )
        self.assertEqual(
            config_module.Config.NANOGPT_BATCH_BASE_URL,
            "https://batch.example.test/v1",
        )
        self.assertEqual(
            config_module.Config.NANOGPT_ORIGIN_URL,
            "https://cake.nano-gpt.com",
        )
        self.assertEqual(config_module.Config.NANOGPT_KEY_CHECK_TIMEOUT_SECONDS, 5)
        self.assertEqual(config_module.Config.NANOGPT_KEY_CHECK_TTL_SECONDS, 300)
        self.assertEqual(
            config_module.Config.NANOGPT_KEY_CHECK_EVERY_REQUESTS,
            50,
        )
        self.assertEqual(
            config_module.Config.NANOGPT_KEY_REJECTED_COOLDOWN_SECONDS,
            60,
        )
        self.assertIs(config_module.Config.PROMPT_CACHE_ENABLED, True)
        self.assertEqual(config_module.Config.PROMPT_CACHE_MIN_TOKENS, 1024)
        self.assertEqual(
            config_module.Config.API_BASE_URLS["navyai"],
            "https://navy.example.test",
        )
        self.assertEqual(
            config_module.Config.API_BASE_URLS["opencode"],
            "https://go.example.test/v1",
        )

    def test_gemini_static_model_list_prefers_current_public_models(self):
        from config import Config

        self.assertEqual(Config.GEMINI_MODELS[0], "gemini-3.6-flash")
        self.assertIn("gemini-3.5-flash", Config.GEMINI_MODELS)
        self.assertIn("gemini-3.5-flash-lite", Config.GEMINI_MODELS)
        self.assertIn("gemini-3.1-pro-preview", Config.GEMINI_MODELS)
        self.assertIn("gemini-3-flash-preview", Config.GEMINI_MODELS)
        self.assertIn("gemini-2.5-pro", Config.GEMINI_MODELS)
        self.assertIn("gemini-2.5-flash", Config.GEMINI_MODELS)
        self.assertNotIn("gemini-3.1-flash-lite-preview", Config.GEMINI_MODELS)
        self.assertNotIn("gemini-2.0-pro", Config.GEMINI_MODELS)
        self.assertNotIn("gemini-1.0-ultra", Config.GEMINI_MODELS)

    def test_gemma_static_model_list_matches_hosted_gemma_4_models(self):
        from config import Config

        self.assertEqual(
            Config.GEMMA_MODELS,
            ["gemma-4-26b-a4b-it", "gemma-4-31b-it"],
        )

    def test_bounded_environment_integer_rejects_invalid_and_extreme_values(self):
        from config import load_bounded_env_integer

        with patch.dict(os.environ, {"TEST_BOUNDED_INTEGER": "invalid"}):
            self.assertEqual(
                load_bounded_env_integer("TEST_BOUNDED_INTEGER", 5, 1, 30),
                5,
            )
        with patch.dict(os.environ, {"TEST_BOUNDED_INTEGER": "99"}):
            self.assertEqual(
                load_bounded_env_integer("TEST_BOUNDED_INTEGER", 5, 1, 30),
                30,
            )

    def test_environment_boolean_accepts_explicit_true_values_only(self):
        from config import load_env_boolean

        with patch.dict(os.environ, {"TEST_BOOLEAN": "yes"}):
            self.assertIs(load_env_boolean("TEST_BOOLEAN", False), True)
        with patch.dict(os.environ, {"TEST_BOOLEAN": "disabled"}):
            self.assertIs(load_env_boolean("TEST_BOOLEAN", True), False)


if __name__ == "__main__":
    unittest.main()
