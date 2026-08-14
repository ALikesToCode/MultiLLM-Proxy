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
        self.assertIn("<code>402</code>", body)
        self.assertIn("semantic <code>max</code>", body)
        self.assertIn("GLM_AUTO_OPTIMIZE_TRIGGER_TOKENS", body)
        self.assertIn("prompt-span offsets only", body)
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

    def test_trusted_worker_headers_preserve_public_https_origin(self):
        os.environ["MULTILLM_TRUST_PROXY_HEADERS"] = "true"
        trusted_app = self.app_module.create_app()
        trusted_app.config["WTF_CSRF_ENABLED"] = False
        trusted_app.config["SESSION_COOKIE_SECURE"] = False
        client = trusted_app.test_client()
        forwarded_headers = {
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "multillm-proxy.cserules.workers.dev",
        }

        login_redirect = client.get(
            "/docs",
            base_url="http://container.internal:8080",
            headers=forwarded_headers,
            follow_redirects=False,
        )
        self.assertEqual(login_redirect.status_code, 302)
        self.assertIn(
            "next=https://multillm-proxy.cserules.workers.dev/docs",
            login_redirect.headers["Location"],
        )

        with client.session_transaction(
            base_url="http://container.internal:8080",
        ) as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_live_admin",
                "scopes": ["admin"],
            }

        response = client.get(
            "/docs.json",
            base_url="http://container.internal:8080",
            headers=forwarded_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["base_url"],
            "https://multillm-proxy.cserules.workers.dev",
        )

    def test_forwarded_origin_is_ignored_without_trusted_proxy_mode(self):
        os.environ.pop("MULTILLM_TRUST_PROXY_HEADERS", None)
        direct_app = self.app_module.create_app()
        client = direct_app.test_client()

        response = client.get(
            "/docs",
            base_url="http://container.internal:8080",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "spoofed.example",
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(
            "next=http://container.internal:8080/docs",
            response.headers["Location"],
        )
        self.assertNotIn("spoofed.example", response.headers["Location"])

    def test_worker_origin_header_wins_after_container_header_normalization(self):
        os.environ["MULTILLM_TRUST_PROXY_HEADERS"] = "true"
        trusted_app = self.app_module.create_app()
        trusted_app.config["WTF_CSRF_ENABLED"] = False
        client = trusted_app.test_client()

        response = client.get(
            "/docs",
            base_url="http://container.internal:8080",
            headers={
                "X-Forwarded-Proto": "http",
                "X-Forwarded-Host": "container.internal:8080",
                "X-MultiLLM-External-Origin": (
                    "https://multillm-proxy.cserules.workers.dev"
                ),
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(
            "next=https://multillm-proxy.cserules.workers.dev/docs",
            response.headers["Location"],
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
