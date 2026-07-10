import json
import logging
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class AppLoggingTest(unittest.TestCase):
    def _inspect_import(self, log_level: str, flask_env: str = "production") -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tempdir:
            env = os.environ.copy()
            env.update(
                {
                    "ADMIN_API_KEY": "logging-test-admin-key",
                    "FLASK_SECRET_KEY": "logging-test-flask-secret",
                    "JWT_SECRET": "logging-test-jwt-secret",
                    "AUTH_DB_PATH": str(Path(tempdir) / "auth.sqlite3"),
                    "RATE_LIMIT_DB_PATH": str(Path(tempdir) / "rate-limits.sqlite3"),
                    "MODEL_REGISTRY_DB_PATH": str(Path(tempdir) / "models.sqlite3"),
                    "FLASK_ENV": flask_env,
                    "LOG_LEVEL": log_level,
                }
            )
            script = """
import json
import logging

import app

root_logger = logging.getLogger()
handler_count = len(root_logger.handlers)
app.create_app()
app.create_app()
print(json.dumps({
    "root_level": root_logger.level,
    "urllib3_level": logging.getLogger("urllib3").level,
    "handler_count_before": handler_count,
    "handler_count_after": len(root_logger.handlers),
    "app_debug": app.app.config["DEBUG"],
}))
"""
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                check=True,
                text=True,
            )

        return json.loads(result.stdout.splitlines()[-1])

    def test_default_and_invalid_levels_fall_back_to_info(self):
        for value in ("", "TRACE", "not-a-level"):
            with self.subTest(value=value):
                state = self._inspect_import(value)
                self.assertEqual(state["root_level"], logging.INFO)

    def test_standard_log_levels_are_accepted_case_insensitively(self):
        expected_levels = {
            "debug": logging.DEBUG,
            "INFO": logging.INFO,
            "Warning": logging.WARNING,
            "ERROR": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        for value, expected in expected_levels.items():
            with self.subTest(value=value):
                state = self._inspect_import(value)
                self.assertEqual(state["root_level"], expected)

    def test_urllib3_never_logs_below_warning(self):
        state = self._inspect_import("DEBUG")

        self.assertGreaterEqual(state["urllib3_level"], logging.WARNING)

    def test_repeated_app_creation_does_not_add_root_handlers(self):
        state = self._inspect_import("INFO")

        self.assertEqual(state["handler_count_after"], state["handler_count_before"])

    def test_development_flask_debug_configuration_is_unchanged(self):
        state = self._inspect_import("INFO", flask_env="development")

        self.assertTrue(state["app_debug"])

    def test_example_environment_documents_production_log_level(self):
        example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")

        self.assertIn("LOG_LEVEL=INFO", example.splitlines())


if __name__ == "__main__":
    unittest.main()
