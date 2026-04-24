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
        self.flask_app = self.app_module.create_app()
        self.flask_app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.flask_app.test_client()

    def tearDown(self):
        self.env_patch.stop()
        self.tempdir.cleanup()

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


if __name__ == "__main__":
    unittest.main()
