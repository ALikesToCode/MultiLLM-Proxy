import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxy import PROVIDER_DETAILS


class KimiCodeMetadataTest(unittest.TestCase):
    repo_root = Path(__file__).resolve().parents[1]

    @staticmethod
    def _clear_runtime_modules():
        for module_name in list(sys.modules):
            if module_name.startswith(("routes.", "providers.")):
                sys.modules.pop(module_name, None)
        for module_name in (
            "app",
            "route_helpers",
            "services.auth_service",
            "services.context_optimizer",
            "services.model_registry",
            "services.proxy_service",
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
                "KIMI_CODE_API_KEY": "kimi-code-test-key",
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
                "session_id": "kimi-code-dashboard-test",
            }

    def tearDown(self):
        self._clear_runtime_modules()
        self.env_patch.stop()
        self.tempdir.cleanup()

    def test_kimi_code_metadata_is_chat_only_and_documents_k3_controls(self):
        details = PROVIDER_DETAILS["kimi-code"]
        endpoint_by_url = {
            endpoint["url"]: endpoint for endpoint in details["endpoints"]
        }

        self.assertIn("https://api.kimi.com/coding/v1", details["description"])
        self.assertEqual(
            set(endpoint_by_url),
            {"/v1/models", "/v1/chat/completions"},
        )
        self.assertNotIn("/v1/responses", endpoint_by_url)
        self.assertEqual(details["default_model"], "k3")
        self.assertTrue(details["supported_features"]["raw_streaming"])

        chat_curl = endpoint_by_url["/v1/chat/completions"]["curl"]
        self.assertIn("$PROXY_BASE_URL/kimi-code/v1/chat/completions", chat_curl)
        self.assertIn("$ADMIN_API_KEY", chat_curl)
        self.assertNotIn("$KIMI_CODE_API_KEY", chat_curl)
        self.assertIn('\\"model\\": \\"k3\\"', chat_curl)
        self.assertIn('\\"reasoning_effort\\": \\"max\\"', chat_curl)
        self.assertIn("prompt_cache_key", chat_curl)

    def test_dashboard_lists_kimi_code_routes_and_operating_boundaries(self):
        def provider_status(provider, details, _app_config):
            return {
                "name": provider.upper(),
                "description": details.get("description", ""),
                "endpoints": details.get("endpoints", []),
                "active": provider == "kimi-code",
                "is_configured": provider == "kimi-code",
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
        self.assertIn('id="kimi-code-native-endpoints"', dashboard)
        self.assertIn("/kimi-code/v1/models", dashboard)
        self.assertIn("/kimi-code/v1/chat/completions", dashboard)
        self.assertIn("https://api.kimi.com/coding/v1", dashboard)
        self.assertIn("KIMI_CODE_API_KEY", dashboard)
        self.assertIn("kimi-code:k3", dashboard)
        self.assertIn("Chat Completions only", dashboard)
        self.assertIn("reasoning_effort: max", dashboard)
        self.assertIn("prompt_cache_key", dashboard)

    def test_docs_cover_kimi_secret_optimizer_cost_and_deployment_commands(self):
        readme = (self.repo_root / "README.md").read_text(encoding="utf-8")
        container_docs = (self.repo_root / "docs/cloudflare-containers.md").read_text(
            encoding="utf-8"
        )
        deployment_docs = (self.repo_root / "docs/deployment-cloudflare.md").read_text(
            encoding="utf-8"
        )
        env_example = (self.repo_root / ".env.example").read_text(encoding="utf-8")
        combined = "\n".join((readme, container_docs, deployment_docs))

        for value in (
            "KIMI_CODE_API_KEY",
            "https://api.kimi.com/coding/v1",
            "kimi-code:k3",
            "/kimi-code/v1/models",
            "/kimi-code/v1/chat/completions",
            'reasoning_effort: "max"',
            "prompt_cache_key",
            "POST /optimize/v1/chat/completions",
            "deterministic",
            "summary_model",
            "allow_cross_provider_summary",
            "eligible historical user/assistant plaintext",
            "additional billed",
            "newest detailed image prompt",
            "provider-neutral byte-based estimates",
            "X-MultiLLM-Estimated-Input-Before",
            "X-MultiLLM-Summary",
        ):
            self.assertIn(value, combined)

        self.assertIn("KIMI_CODE_API_KEY=your-kimi-code-api-key", env_example)
        self.assertIn("OPTIMIZER_MAX_REQUEST_BYTES=16777216", env_example)
        self.assertIn("OPTIMIZER_SUMMARY_TIMEOUT_SECONDS=45", env_example)
        self.assertIn("normal `/v1/chat/completions`", combined.lower())
        self.assertIn("remain unchanged", combined)
        self.assertIn("npm ci", container_docs)
        self.assertIn("npm ci", deployment_docs)
        self.assertNotIn("pnpm install", container_docs)
        self.assertNotIn("pnpm install", deployment_docs)


if __name__ == "__main__":
    unittest.main()
