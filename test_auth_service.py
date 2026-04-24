import importlib
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from flask import Flask
from werkzeug.security import generate_password_hash


class AuthServicePersistenceTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env_patch = patch.dict(
            os.environ,
            {
                "ADMIN_USERNAME": "admin",
                "ADMIN_API_KEY": "seed-admin-key",
                "AUTH_DB_PATH": os.path.join(self.tempdir.name, "auth.sqlite3"),
                "JWT_SECRET": "jwt-test-secret",
            },
            clear=False,
        )
        self.env_patch.start()

        self.auth_module = importlib.import_module("services.auth_service")
        self.auth_module = importlib.reload(self.auth_module)
        self.AuthService = self.auth_module.AuthService

        self.flask_app = Flask(__name__)
        self.flask_app.secret_key = "test-secret"

    def tearDown(self):
        self.env_patch.stop()
        self.tempdir.cleanup()

    def _reset_auth_runtime_state(self):
        self.AuthService._users = {}
        self.AuthService._api_keys = {}
        self.AuthService._google_token = None
        self.AuthService._google_token_expiry = None
        if hasattr(self.AuthService, "_storage_initialized"):
            self.AuthService._storage_initialized = False
        if hasattr(self.AuthService, "_storage_path"):
            self.AuthService._storage_path = None

    def _authenticate(self, username, api_key):
        with self.flask_app.test_request_context("/login"):
            return self.AuthService.authenticate_user(username, api_key)

    def test_created_users_survive_reinitialize(self):
        self.AuthService.initialize()

        with patch.object(
            self.AuthService,
            "get_current_user",
            return_value={"username": "admin", "is_admin": True},
        ):
            created_user = self.AuthService.create_user("alice", is_admin=False)

        self._reset_auth_runtime_state()
        self.AuthService.initialize()

        self.assertIn("alice", self.AuthService._users)
        self.assertTrue(self._authenticate("alice", created_user["api_key"]))
        self.assertNotIn("api_key", self.AuthService._users["alice"])

    def test_rotated_keys_replace_old_key_after_reinitialize(self):
        self.AuthService.initialize()

        with patch.object(
            self.AuthService,
            "get_current_user",
            return_value={"username": "admin", "is_admin": True},
        ):
            created_user = self.AuthService.create_user("bob", is_admin=False)
            rotated_user = self.AuthService.rotate_api_key("bob")

        self._reset_auth_runtime_state()
        self.AuthService.initialize()

        self.assertFalse(self._authenticate("bob", created_user["api_key"]))
        self.assertTrue(self._authenticate("bob", rotated_user["api_key"]))

    def test_users_table_does_not_store_plaintext_api_keys(self):
        self.AuthService.initialize()

        db_path = os.environ["AUTH_DB_PATH"]
        with sqlite3.connect(db_path) as connection:
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }

        self.assertNotIn("api_key", columns)
        self.assertIn("api_key_hash", columns)
        self.assertIn("api_key_prefix", columns)

    def test_legacy_plaintext_api_key_table_is_migrated(self):
        db_path = os.environ["AUTH_DB_PATH"]
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                """
                CREATE TABLE users (
                    username TEXT PRIMARY KEY,
                    api_key TEXT NOT NULL,
                    api_key_hash TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_login TEXT
                )
                """
            )
            connection.execute(
                """
                INSERT INTO users (
                    username, api_key, api_key_hash, is_admin, created_at, last_login
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy",
                    "legacy-secret-key",
                    generate_password_hash("legacy-secret-key"),
                    0,
                    "2026-04-24T00:00:00+00:00",
                    None,
                ),
            )
            connection.commit()

        self.AuthService.initialize()

        with sqlite3.connect(db_path) as connection:
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            row = connection.execute(
                "SELECT api_key_prefix FROM users WHERE username = ?",
                ("legacy",),
            ).fetchone()

        self.assertNotIn("api_key", columns)
        self.assertEqual(row[0], "mllm_legacy-s")
        self.assertTrue(self._authenticate("legacy", "legacy-secret-key"))

    def test_authentication_session_omits_api_key_material(self):
        self.AuthService.initialize()

        with patch.object(
            self.AuthService,
            "get_current_user",
            return_value={"username": "admin", "is_admin": True},
        ):
            created_user = self.AuthService.create_user("carol", is_admin=False)

        with self.flask_app.test_request_context("/login"):
            self.assertTrue(
                self.AuthService.authenticate_user("carol", created_user["api_key"])
            )
            session_user = self.auth_module.session["user"]

        self.assertNotIn("api_key", session_user)
        self.assertNotIn(created_user["api_key"], str(session_user))
        self.assertEqual(session_user["api_key_prefix"], created_user["api_key_prefix"])

    def test_list_users_returns_prefix_not_plaintext_key(self):
        self.AuthService.initialize()

        with patch.object(
            self.AuthService,
            "get_current_user",
            return_value={"username": "admin", "is_admin": True},
        ):
            created_user = self.AuthService.create_user("dana", is_admin=False)
            users = self.AuthService.list_users()

        dana = next(user for user in users if user["username"] == "dana")
        self.assertNotIn("api_key", dana)
        self.assertEqual(dana["api_key_prefix"], created_user["api_key_prefix"])
        self.assertNotIn(created_user["api_key"], str(users))

    def test_verify_api_key_uses_hash_only_and_tracks_usage(self):
        self.AuthService.initialize()

        with patch.object(
            self.AuthService,
            "get_current_user",
            return_value={"username": "admin", "is_admin": True},
        ):
            created_user = self.AuthService.create_user("erin", is_admin=False)

        verified_user = self.AuthService.verify_api_key(
            created_user["api_key"],
            remote_addr="203.0.113.10",
        )

        self.assertIsNotNone(verified_user)
        self.assertEqual(verified_user["username"], "erin")
        self.assertNotIn("api_key", verified_user)
        self.assertEqual(self.AuthService._users["erin"]["last_used_ip"], "203.0.113.10")
        self.assertIsNotNone(self.AuthService._users["erin"]["last_used_at"])

    def test_groq_provider_key_uses_first_numbered_key_when_direct_key_absent(self):
        with patch.dict(
            os.environ,
            {
                "GROQ_API_KEY": "",
                "GROQ_API_KEY_2": "groq-second",
                "GROQ_API_KEY_1": "groq-first",
            },
            clear=False,
        ):
            self.AuthService.initialize()

        self.assertEqual(self.AuthService.get_api_key("groq"), "groq-first")


if __name__ == "__main__":
    unittest.main()
