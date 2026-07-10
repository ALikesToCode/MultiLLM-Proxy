import importlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from proxy import PROVIDER_DETAILS


class LinkAPIMetadataTest(unittest.TestCase):
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
                "LINKAPI_KEY": "linkapi-test-key",
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
                "session_id": "linkapi-dashboard-test",
            }

    def tearDown(self):
        self._clear_runtime_modules()
        self.env_patch.stop()
        self.tempdir.cleanup()

    def test_linkapi_is_exposed_in_provider_and_dashboard_metadata(self):
        details = PROVIDER_DETAILS["linkapi"]
        endpoint_urls = {endpoint["url"] for endpoint in details["endpoints"]}

        self.assertIn("native Claude", details["description"])
        self.assertEqual(
            endpoint_urls,
            {
                "/v1/messages",
                "/v1/responses",
                "/v1/chat/completions",
                "/v1beta/models/{model}:generateContent",
            },
        )
        self.assertTrue(details["supported_features"]["raw_streaming"])

    def test_rendered_dashboard_lists_linkapi_native_routes_and_caller_auth(self):
        def provider_status(provider, details, _app_config):
            return {
                "name": provider.upper(),
                "description": details.get("description", ""),
                "endpoints": details.get("endpoints", []),
                "active": provider == "linkapi",
                "is_configured": provider == "linkapi",
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
        self.assertIn('id="linkapi-native-endpoints"', dashboard)
        for endpoint in (
            "/linkapi/v1/messages",
            "/linkapi/v1/responses",
            "/linkapi/v1/chat/completions",
            "/linkapi/v1beta/models/{model}:generateContent",
        ):
            self.assertIn(endpoint, dashboard)
        self.assertIn("x-api-key: YOUR_API_KEY", dashboard)
        self.assertIn("Authorization: Bearer YOUR_API_KEY", dashboard)
        self.assertIn("x-goog-api-key: YOUR_API_KEY", dashboard)
        self.assertNotIn("?key=YOUR_API_KEY", dashboard)
        self.assertIn(
            "bypass Flask user, request-size, rate-limit, and metrics controls",
            dashboard,
        )
        self.assertIn("linkapi:&lt;model&gt;", dashboard)


if __name__ == "__main__":
    unittest.main()
