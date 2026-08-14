import unittest

from config import Config
from providers.registry import PROVIDER_SPECS, build_default_registry
from proxy import PROVIDER_DETAILS
from services.auth_service import AuthService
from services.transport_policy import provider_circuit_mode


class FeatureInventoryTest(unittest.TestCase):
    def test_every_configured_provider_has_operator_metadata_and_limits(self):
        configured = set(Config.API_BASE_URLS)

        self.assertEqual(set(PROVIDER_DETAILS), configured)
        self.assertTrue(configured.issubset(Config.API_TIMEOUTS))

        for provider in configured:
            with self.subTest(provider=provider):
                details = PROVIDER_DETAILS[provider]
                self.assertTrue(details.get("description"))
                self.assertTrue(details.get("endpoints"))
                self.assertTrue(AuthService.provider_credential_env_names(provider))
                if provider not in Config.API_RETRIES:
                    self.assertEqual(provider_circuit_mode(provider), "bypassed")

    def test_every_openai_compatible_provider_spec_builds_an_adapter(self):
        registry = build_default_registry(Config.API_BASE_URLS)
        expected = {provider for provider, _path, _capabilities in PROVIDER_SPECS}

        self.assertEqual(set(registry), expected)
        for provider, adapter in registry.items():
            with self.subTest(provider=provider):
                self.assertTrue(adapter.capabilities().supports_chat)
                self.assertTrue(adapter.chat_completions_url().startswith("https://"))


if __name__ == "__main__":
    unittest.main()
