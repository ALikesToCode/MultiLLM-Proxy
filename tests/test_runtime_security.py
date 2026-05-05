import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
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

    def test_create_app_keeps_environment_config_and_cookie_hardening_order(self):
        with tempfile.TemporaryDirectory() as tempdir:
            with patch.dict(
                os.environ,
                {
                    "FLASK_ENV": "development",
                    "ADMIN_API_KEY": "admin-live-key",
                    "FLASK_SECRET_KEY": "flask-live-secret",
                    "JWT_SECRET": "jwt-live-secret",
                    "AUTH_DB_PATH": os.path.join(tempdir, "auth.sqlite3"),
                },
                clear=False,
            ):
                sys.modules.pop("app", None)
                app_module = importlib.import_module("app")

                flask_app = app_module.create_app()

        self.assertTrue(flask_app.config["DEBUG"])
        self.assertTrue(flask_app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(flask_app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertFalse(flask_app.config["SESSION_COOKIE_SECURE"])

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

    def test_vercel_init_defaults_sqlite_paths_to_tmp_on_vercel(self):
        with patch.dict(
            os.environ,
            {
                "VERCEL": "1",
                "AUTH_DB_PATH": "",
                "RATE_LIMIT_DB_PATH": "",
                "MODEL_REGISTRY_DB_PATH": "",
            },
            clear=False,
        ):
            vercel_module = importlib.import_module("vercel")
            vercel_module = importlib.reload(vercel_module)

            vercel_module.init_vercel()

            self.assertEqual(os.environ["AUTH_DB_PATH"], "/tmp/multillm-auth.sqlite3")
            self.assertEqual(os.environ["RATE_LIMIT_DB_PATH"], "/tmp/multillm-rate-limits.sqlite3")
            self.assertEqual(os.environ["MODEL_REGISTRY_DB_PATH"], "/tmp/multillm-model-registry.sqlite3")

    def test_service_worker_does_not_cache_login_or_authenticated_navigation(self):
        service_worker = Path(__file__).resolve().parents[1] / "static" / "service-worker.js"
        source = service_worker.read_text(encoding="utf-8")
        navigate_block = source.split("if (event.request.mode === 'navigate')", 1)[1].split(
            "if (",
            1,
        )[0]

        self.assertNotIn("'/login'", source)
        self.assertNotIn('"/login"', source)
        self.assertNotIn("cache.put", navigate_block)

    def test_env_loader_prefers_env_local_over_env_without_overriding_shell(self):
        env_loader = importlib.import_module("env_loader")
        env_loader = importlib.reload(env_loader)

        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / ".env").write_text(
                "ADMIN_API_KEY=from-env\n"
                "FLASK_SECRET_KEY=from-env\n",
                encoding="utf-8",
            )
            (root / ".env.local").write_text(
                "ADMIN_API_KEY=from-env-local\n"
                "JWT_SECRET=from-env-local\n",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"FLASK_SECRET_KEY": "from-shell"}, clear=True):
                env_loader.load_runtime_env(root=root)

                self.assertEqual(os.environ["ADMIN_API_KEY"], "from-env-local")
                self.assertEqual(os.environ["JWT_SECRET"], "from-env-local")
                self.assertEqual(os.environ["FLASK_SECRET_KEY"], "from-shell")

    def test_index_initializes_vercel_before_importing_app(self):
        with tempfile.TemporaryDirectory() as tempdir:
            with patch.dict(
                os.environ,
                {
                    "ADMIN_API_KEY": "",
                    "VERCEL_ADMIN_API_KEY": "vercel-admin-key",
                    "FLASK_SECRET_KEY": "flask-live-secret",
                    "JWT_SECRET": "jwt-live-secret",
                    "AUTH_DB_PATH": os.path.join(tempdir, "auth.sqlite3"),
                },
                clear=False,
            ):
                for module_name in ("index", "app"):
                    sys.modules.pop(module_name, None)

                index_module = importlib.import_module("index")

                self.assertEqual(os.environ["ADMIN_API_KEY"], "vercel-admin-key")
                self.assertIsNotNone(index_module.app)


if __name__ == "__main__":
    unittest.main()
