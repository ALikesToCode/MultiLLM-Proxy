import importlib
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


class SQLiteSchemaTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ.update(
            {
                "ADMIN_USERNAME": "admin",
                "ADMIN_API_KEY": "admin-test-key",
                "FLASK_SECRET_KEY": "flask-test-secret",
                "JWT_SECRET": "jwt-test-secret",
                "AUTH_DB_PATH": os.path.join(self.temp_dir.name, "auth.sqlite3"),
                "RATE_LIMIT_DB_PATH": os.path.join(self.temp_dir.name, "limits.sqlite3"),
                "MODEL_REGISTRY_DB_PATH": os.path.join(self.temp_dir.name, "models.sqlite3"),
            }
        )

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    @staticmethod
    def _indexes(connection, table_name):
        return {
            row[1]
            for row in connection.execute(f"PRAGMA index_list({table_name})").fetchall()  # nosec B608
        }

    def test_auth_storage_adds_api_key_prefix_index(self):
        auth_module = importlib.import_module("services.auth_service")
        auth_module = importlib.reload(auth_module)
        auth_module.AuthService.initialize()

        with sqlite3.connect(os.environ["AUTH_DB_PATH"]) as connection:
            self.assertIn("idx_users_api_key_prefix", self._indexes(connection, "users"))

    def test_rate_limit_storage_adds_retention_cleanup_index(self):
        rate_module = importlib.import_module("services.rate_limit_service")
        rate_module = importlib.reload(rate_module)

        with rate_module.closing(rate_module.RateLimitService._connect()) as connection:
            rate_module.RateLimitService._ensure_storage(connection)
            connection.commit()
            indexes = self._indexes(connection, "request_usage")

        self.assertIn("idx_request_usage_window", indexes)
        self.assertIn("idx_request_usage_created_at", indexes)

    def test_model_status_uses_single_row_lookup(self):
        model_module = importlib.import_module("services.model_registry")
        model_module = importlib.reload(model_module)
        model_module.ModelRegistry.disable_model("opencode:kimi-k2.6")

        with patch.object(
            model_module.ModelRegistry,
            "_status_overrides",
            side_effect=AssertionError("bulk override load should not run"),
        ):
            status = model_module.ModelRegistry.get_model_status("opencode:kimi-k2.6")

        self.assertEqual(status, "disabled")


if __name__ == "__main__":
    unittest.main()
