import json
import unittest

from config import Config
from providers.base import CanonicalRequest
from providers.registry import build_default_registry, get_adapter


class ProviderAdapterRegistryTest(unittest.TestCase):
    def test_default_registry_resolves_initial_adapter_slice(self):
        registry = build_default_registry(Config.API_BASE_URLS)

        for provider in ("openai", "openrouter", "gemini", "groq", "opencode"):
            with self.subTest(provider=provider):
                self.assertIn(provider, registry)
                self.assertTrue(registry[provider].capabilities().supports_chat)

    def test_chat_completion_urls_match_legacy_routes(self):
        registry = build_default_registry(Config.API_BASE_URLS)

        self.assertEqual(
            registry["openrouter"].chat_completions_url(),
            "https://openrouter.ai/api/v1/chat/completions",
        )
        self.assertEqual(
            registry["groq"].chat_completions_url(),
            "https://api.groq.com/openai/v1/chat/completions",
        )
        self.assertEqual(
            registry["opencode"].chat_completions_url(),
            "https://opencode.ai/zen/go/v1/chat/completions",
        )
        self.assertEqual(
            registry["gemini"].chat_completions_url(),
            "https://generativelanguage.googleapis.com/v1beta/chat/completions",
        )

    def test_adapter_prepares_openai_compatible_request(self):
        adapter = get_adapter("openrouter", Config.API_BASE_URLS)
        request = adapter.prepare_request(
            CanonicalRequest(
                provider="openrouter",
                model="openai/gpt-4o-mini",
                messages=[{"role": "user", "content": "Hello"}],
                stream=True,
            )
        )

        payload = json.loads(request.data)

        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url, "https://openrouter.ai/api/v1/chat/completions")
        self.assertEqual(payload["model"], "openai/gpt-4o-mini")
        self.assertTrue(payload["stream"])
        self.assertEqual(payload["messages"][0]["role"], "user")


if __name__ == "__main__":
    unittest.main()
