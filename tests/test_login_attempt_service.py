import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services.login_attempt_service import LoginAttemptService


class LoginAttemptServiceTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "limits.sqlite3")
        self.env_patch = patch.dict(
            os.environ,
            {
                "JWT_SECRET": "login-attempt-test-secret",
                "RATE_LIMIT_DB_PATH": self.db_path,
                "LOGIN_MAX_ATTEMPTS": "3",
                "LOGIN_ATTEMPT_WINDOW_SECONDS": "60",
                "LOGIN_LOCKOUT_SECONDS": "120",
                "LOGIN_MAX_TRACKED_IDENTITIES": "100",
            },
            clear=False,
        )
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.tempdir.cleanup()

    def test_locks_identity_after_configured_failures(self):
        self.assertTrue(LoginAttemptService.record_failure("192.0.2.4", "admin", now=10).allowed)
        self.assertTrue(LoginAttemptService.record_failure("192.0.2.4", "admin", now=11).allowed)

        decision = LoginAttemptService.record_failure("192.0.2.4", "admin", now=12)

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.retry_after, 120)
        blocked = LoginAttemptService.check("192.0.2.4", "admin", now=20)
        self.assertFalse(blocked.allowed)
        self.assertEqual(blocked.retry_after, 112)

    def test_success_clears_failure_state(self):
        LoginAttemptService.record_failure("192.0.2.5", "admin", now=10)

        LoginAttemptService.record_success("192.0.2.5", "admin")

        self.assertTrue(LoginAttemptService.check("192.0.2.5", "admin", now=11).allowed)
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0], 0)

    def test_expired_window_resets_failure_count(self):
        LoginAttemptService.record_failure("192.0.2.6", "admin", now=10)
        LoginAttemptService.record_failure("192.0.2.6", "admin", now=11)

        decision = LoginAttemptService.record_failure("192.0.2.6", "admin", now=80)

        self.assertTrue(decision.allowed)
        with sqlite3.connect(self.db_path) as connection:
            failures = connection.execute(
                "SELECT failures FROM login_attempts"
            ).fetchone()[0]
        self.assertEqual(failures, 1)

    def test_storage_does_not_retain_raw_identity_values(self):
        LoginAttemptService.record_failure("203.0.113.99", "sensitive-user", now=10)

        database_bytes = Path(self.db_path).read_bytes()

        self.assertNotIn(b"203.0.113.99", database_bytes)
        self.assertNotIn(b"sensitive-user", database_bytes)


if __name__ == "__main__":
    unittest.main()
