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

        self.assertIn("gemini-3.1-pro-preview", Config.GEMINI_MODELS)
        self.assertIn("gemini-3-flash-preview", Config.GEMINI_MODELS)
        self.assertIn("gemini-2.5-pro", Config.GEMINI_MODELS)
        self.assertIn("gemini-2.5-flash", Config.GEMINI_MODELS)
        self.assertNotIn("gemini-2.0-pro", Config.GEMINI_MODELS)
        self.assertNotIn("gemini-1.0-ultra", Config.GEMINI_MODELS)


if __name__ == "__main__":
    unittest.main()
