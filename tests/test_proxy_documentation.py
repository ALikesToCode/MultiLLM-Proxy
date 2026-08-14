import os

from services.provider_catalog_service import ProviderCatalogService
from tests.unified_api_test_case import UnifiedApiTestCase


class ProxyDocumentationTest(UnifiedApiTestCase):
    def _authenticate(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

    def test_live_setup_guide_requires_dashboard_login(self):
        response = self.client.get("/docs", follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_live_setup_guide_combines_safe_runtime_configuration(self):
        os.environ["NANOGPT_API_KEY"] = "nano-secret-never-render"
        ProviderCatalogService.replace_provider_models(
            "opencode",
            ("live-only-model",),
            discovered_at="2026-08-14T10:00:00+00:00",
        )
        self._authenticate()

        response = self.client.get("/docs")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("One proxy. Explicit contracts.", body)
        self.assertIn('href="/docs"', body)
        self.assertIn("/v1/chat/completions", body)
        self.assertIn("/v1/images/generations", body)
        self.assertIn("auto:glm-5.2", body)
        self.assertIn("opencode:live-only-model", body)
        self.assertIn("OPENCODE_GO_API_KEY", body)
        self.assertIn("NANOGPT_API_KEY_1", body)
        self.assertIn("Images deliberately do not use", body)
        self.assertNotIn("opencode-provider-key", body)
        self.assertNotIn("nano-secret-never-render", body)

    def test_live_json_lists_capabilities_models_and_saved_routes(self):
        ProviderCatalogService.replace_provider_models(
            "opencode",
            ("live-only-model",),
        )
        self._authenticate()

        response = self.client.get("/docs.json")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        providers = {provider["id"]: provider for provider in payload["providers"]}
        models = {model["id"]: model for model in payload["models"]}
        self.assertTrue(providers["opencode"]["configured"])
        self.assertTrue(providers["linkapi"]["unified_images"])
        self.assertFalse(providers["opencode"]["unified_images"])
        self.assertEqual(models["opencode:live-only-model"]["sources"], ["live"])
        self.assertTrue(
            models["opencode:live-only-model"]["capabilities"]["supports_chat"]
        )
        self.assertIn("auto:glm-5.2", models)
        self.assertEqual(payload["auto_routes"][0]["id"], "auto:glm-5.2")


if __name__ == "__main__":
    import unittest

    unittest.main()
