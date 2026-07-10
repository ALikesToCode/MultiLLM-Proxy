import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxy import PROVIDER_DETAILS


class CodexEasyMetadataTest(unittest.TestCase):
    repo_root = Path(__file__).resolve().parents[1]

    @staticmethod
    def _clear_runtime_modules():
        for module_name in list(sys.modules):
            if module_name.startswith("routes."):
                sys.modules.pop(module_name, None)
        for module_name in (
            "app",
            "route_helpers",
            "services.auth_service",
            "services.rate_limit_service",
        ):
            sys.modules.pop(module_name, None)

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env_patch = patch.dict(
            os.environ,
            {
                "ADMIN_USERNAME": "admin",
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "AUTH_DB_PATH": os.path.join(self.tempdir.name, "auth.sqlite3"),
                "RATE_LIMIT_DB_PATH": os.path.join(
                    self.tempdir.name,
                    "rate-limits.sqlite3",
                ),
                "MODEL_REGISTRY_DB_PATH": os.path.join(
                    self.tempdir.name,
                    "models.sqlite3",
                ),
                "CODEX_EASY_API_KEY": "codex-easy-test-key",
            },
            clear=False,
        )
        self.env_patch.start()
        self._clear_runtime_modules()

        self.app_module = importlib.import_module("app")
        self.flask_app = self.app_module.create_app()
        self.client = self.flask_app.test_client()
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "admin-test",
                "scopes": ["admin"],
                "session_id": "codex-easy-dashboard-test",
            }

    def tearDown(self):
        self._clear_runtime_modules()
        self.env_patch.stop()
        self.tempdir.cleanup()

    def test_codex_everywhere_metadata_is_dynamic_and_conservative(self):
        details = PROVIDER_DETAILS["codex-easy"]
        endpoint_by_url = {
            endpoint["url"]: endpoint for endpoint in details["endpoints"]
        }

        self.assertIn("Codex Everywhere", details["description"])
        self.assertEqual(
            set(endpoint_by_url),
            {
                "/v1/models",
                "/v1/responses",
                "/v1/chat/completions",
                "/v1/images/generations",
            },
        )
        self.assertEqual(
            details["supported_features"],
            {"streaming": True, "raw_streaming": True},
        )
        self.assertNotIn("default_model", details)

        for endpoint in endpoint_by_url.values():
            self.assertIn("$PROXY_BASE_URL/codex-easy", endpoint["curl"])
            self.assertIn("$ADMIN_API_KEY", endpoint["curl"])
            self.assertNotIn("$CODEX_EASY_API_KEY", endpoint["curl"])

        responses_curl = endpoint_by_url["/v1/responses"]["curl"]
        self.assertIn("grok-4.5", responses_curl)
        self.assertIn("reasoning", responses_curl)
        self.assertIn("effort", responses_curl)
        self.assertIn("high", responses_curl)
        self.assertIn("prompt_cache_key", responses_curl)

        chat_curl = endpoint_by_url["/v1/chat/completions"]["curl"]
        self.assertIn("reasoning_effort", chat_curl)
        self.assertIn("X-Grok-Conv-Id", chat_curl)

    def test_rendered_dashboard_lists_codex_everywhere_routes_and_boundaries(self):
        def provider_status(provider, details, _app_config):
            return {
                "name": provider.upper(),
                "description": details.get("description", ""),
                "endpoints": details.get("endpoints", []),
                "active": provider == "codex-easy",
                "is_configured": provider == "codex-easy",
                "requests_24h": 0,
                "success_rate": 0,
                "error_rate": 0,
                "errors": 0,
                "avg_latency": 0,
                "p95_latency": 0,
                "last_request_at": None,
            }

        with patch("routes.core.check_provider", side_effect=provider_status):
            response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        dashboard = response.get_data(as_text=True)
        self.assertIn('id="codex-easy-native-endpoints"', dashboard)
        for endpoint in (
            "/codex-easy/v1/models",
            "/codex-easy/v1/responses",
            "/codex-easy/v1/chat/completions",
            "/codex-easy/v1/images/generations",
        ):
            self.assertIn(endpoint, dashboard)
        self.assertIn("Authorization: Bearer YOUR_API_KEY", dashboard)
        self.assertIn(
            "bypass Flask user, request-size, rate-limit, and metrics controls",
            dashboard,
        )
        self.assertIn("codex-easy:&lt;model&gt;", dashboard)
        self.assertIn("CODEX_EASY_API_KEY", dashboard)
        self.assertIn("image-generation key groups", dashboard)

    def test_codex_everywhere_docs_cover_dynamic_catalog_cache_and_base_urls(self):
        readme = (self.repo_root / "README.md").read_text(encoding="utf-8")
        container_docs = (self.repo_root / "docs/cloudflare-containers.md").read_text(
            encoding="utf-8"
        )
        deployment_docs = (self.repo_root / "docs/deployment-cloudflare.md").read_text(
            encoding="utf-8"
        )
        combined = "\n".join((readme, container_docs, deployment_docs))

        for value in (
            "CODEX_EASY_API_KEY",
            "CODEX_API_KEY",
            "https://codex-easy.ai",
            "$PROXY_BASE_URL/codex-easy",
            "$PROXY_BASE_URL/codex-easy/v1",
            "/codex-easy/v1/models",
            "/codex-easy/v1/responses",
            "/codex-easy/v1/chat/completions",
            "/codex-easy/v1/images/*",
            "prompt_cache_key",
            "X-Grok-Conv-Id",
            "image-generation key groups",
        ):
            self.assertIn(value, combined)

        self.assertIn('"reasoning":{"effort":"high"}', readme)
        self.assertIn('"reasoning_effort":"high"', readme)
        self.assertIn("key-group", combined)
        self.assertIn("both raw openai fast paths", combined.lower())
        self.assertIn("/codex-easy/v1/*", combined)
        self.assertIn("/linkapi/v1/*", combined)
        self.assertIn("xAI", combined)
        self.assertIn("do not guarantee a cache hit", combined)
        self.assertIn("does not provide idempotency", combined)


if __name__ == "__main__":
    unittest.main()
