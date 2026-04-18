import importlib
import os
import tempfile
import unittest
from unittest.mock import patch

from flask import Flask


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


if __name__ == "__main__":
    unittest.main()
