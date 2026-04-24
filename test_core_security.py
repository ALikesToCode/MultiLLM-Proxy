import importlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch


class LoginRedirectSecurityTest(unittest.TestCase):
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
            },
            clear=False,
        )
        self.env_patch.start()

        for module_name in ("app", "services.auth_service", "routes.core"):
            sys.modules.pop(module_name, None)

        self.app_module = importlib.import_module("app")
        self.error_handlers_module = importlib.import_module("error_handlers")
        self.flask_app = self.app_module.create_app()
        self.flask_app.config["WTF_CSRF_ENABLED"] = False

        @self.flask_app.route("/test/unhandled-error")
        def unhandled_error():
            raise RuntimeError("MetricsService.track_request() got an unexpected keyword argument 'endpoint'")

        @self.flask_app.route("/test/client-api-error")
        def client_api_error():
            raise self.error_handlers_module.APIError("Model is required", status_code=400)

        @self.flask_app.route("/test/server-api-error")
        def server_api_error():
            raise self.error_handlers_module.APIError("provider secret sk-live-abc123 leaked", status_code=500)

        self.client = self.flask_app.test_client()

    def tearDown(self):
        self.env_patch.stop()
        self.tempdir.cleanup()

    def _set_admin_session(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["user"] = {
                "username": "admin",
                "is_admin": True,
                "api_key_prefix": "mllm_admin",
                "scopes": ["admin"],
                "session_id": "test-session",
            }

    def test_login_rejects_external_next_redirect(self):
        response = self.client.post(
            "/login?next=https://evil.example/path",
            data={"username": "admin", "api_key": "admin-test-key"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

    def test_login_allows_local_next_redirect(self):
        response = self.client.post(
            "/login?next=/users",
            data={"username": "admin", "api_key": "admin-test-key"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/users")

    def test_session_cookie_is_hardened_in_production(self):
        self.flask_app.config["SESSION_COOKIE_SECURE"] = True
        response = self.client.post(
            "/login",
            data={"username": "admin", "api_key": "admin-test-key"},
            follow_redirects=False,
        )

        cookie_header = response.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie_header)
        self.assertIn("Secure", cookie_header)
        self.assertIn("SameSite=Lax", cookie_header)

    def test_unexpected_errors_are_opaque_and_include_request_id(self):
        self._set_admin_session()
        response = self.client.get(
            "/test/unhandled-error",
            headers={
                "Accept": "application/json",
                "X-Request-ID": "req-test-123",
            },
        )

        self.assertEqual(response.status_code, 500)
        payload = response.get_json()
        self.assertEqual(payload["error"], "internal_error")
        self.assertEqual(payload["message"], "An unexpected error occurred.")
        self.assertEqual(payload["request_id"], "req-test-123")
        self.assertEqual(response.headers["X-Request-ID"], "req-test-123")
        response_text = response.get_data(as_text=True)
        self.assertNotIn("MetricsService.track_request", response_text)
        self.assertNotIn("endpoint", response_text)

    def test_expected_client_api_errors_keep_message(self):
        self._set_admin_session()
        response = self.client.get(
            "/test/client-api-error",
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertEqual(payload["message"], "Model is required")
        self.assertIn("request_id", payload)

    def test_server_api_errors_are_opaque(self):
        self._set_admin_session()
        response = self.client.get(
            "/test/server-api-error",
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 500)
        payload = response.get_json()
        self.assertEqual(payload["error"], "internal_error")
        self.assertEqual(payload["message"], "An unexpected error occurred.")
        self.assertIn("request_id", payload)
        self.assertNotIn("sk-live", response.get_data(as_text=True))

    def test_json_errors_accept_wildcard_accept_header(self):
        self._set_admin_session()
        response = self.client.get(
            "/test/client-api-error",
            headers={"Accept": "*/*"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content_type, "application/json")
        self.assertEqual(response.get_json()["message"], "Model is required")

    def test_not_found_html_includes_request_id(self):
        response = self.client.get(
            "/static/missing-page.txt",
            headers={"X-Request-ID": "req-missing-page"},
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn("req-missing-page", response.get_data(as_text=True))

    def test_json_user_create_parses_is_admin_strings_strictly(self):
        self._set_admin_session()
        response = self.client.post(
            "/users",
            headers={"Accept": "application/json"},
            json={"username": "jsonfalse", "is_admin": "false"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["user"]["is_admin"])

    def test_json_user_create_rejects_ambiguous_is_admin_string(self):
        self._set_admin_session()
        response = self.client.post(
            "/users",
            headers={"Accept": "application/json"},
            json={"username": "badflag", "is_admin": "definitely"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("is_admin must be a boolean", response.get_json()["message"])


if __name__ == "__main__":
    unittest.main()
