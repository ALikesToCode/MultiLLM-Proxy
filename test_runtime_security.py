import importlib
import os
import sys
import unittest
from unittest.mock import patch


class RuntimeSecurityConfigTest(unittest.TestCase):
    def test_create_app_rejects_placeholder_secrets(self):
        with patch.dict(
            os.environ,
            {
                "ADMIN_API_KEY": "admin-live-key",
                "FLASK_SECRET_KEY": "your-flask-secret-key",
                "JWT_SECRET": "your-jwt-secret-key",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "FLASK_SECRET_KEY"):
                sys.modules.pop("app", None)
                importlib.import_module("app")

    def test_create_app_requires_admin_api_key(self):
        with patch.dict(
            os.environ,
            {
                "ADMIN_API_KEY": "",
                "FLASK_SECRET_KEY": "flask-live-secret",
                "JWT_SECRET": "jwt-live-secret",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "ADMIN_API_KEY"):
                sys.modules.pop("app", None)
                importlib.import_module("app")

    def test_vercel_init_does_not_invent_default_admin_key(self):
        with patch.dict(
            os.environ,
            {
                "FLASK_ENV": "",
                "ADMIN_API_KEY": "",
            },
            clear=False,
        ):
            vercel_module = importlib.import_module("vercel")
            vercel_module = importlib.reload(vercel_module)

            vercel_module.init_vercel()
            self.assertNotEqual(os.environ.get("ADMIN_API_KEY"), "default-key")


if __name__ == "__main__":
    unittest.main()
