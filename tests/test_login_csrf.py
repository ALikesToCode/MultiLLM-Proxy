import re
import time
from unittest.mock import patch

from tests.unified_api_test_case import UnifiedApiTestCase


class LoginCsrfTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config["WTF_CSRF_ENABLED"] = True

    def token(self, response):
        match = re.search(
            r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True)
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def assert_recoverable(self, token=None):
        data = {"username": "csrf-test", "api_key": "must-not-be-rendered"}
        if token is not None:
            data["csrf_token"] = token
        with patch("routes.core.AuthService.authenticate_user", return_value=False) as auth:
            response = self.client.post("/login", data=data)
            self.assertEqual(response.status_code, 400)
            auth.assert_not_called()
            body = response.get_data(as_text=True)
            self.assertIn("A fresh form is ready below", body)
            self.assertNotIn("must-not-be-rendered", body)
            self.assertNotIn("csrf-test", body)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            data["csrf_token"] = self.token(response)
            retry = self.client.post("/login", data=data)
            self.assertEqual(retry.status_code, 401)
            auth.assert_called_once_with("csrf-test", "must-not-be-rendered")

    def test_missing_token_gets_fresh_form_without_authentication(self):
        self.assert_recoverable()

    def test_invalid_token_gets_fresh_form_without_authentication(self):
        self.client.get("/login")
        self.assert_recoverable("invalid-token")

    def test_expired_signed_token_gets_fresh_form(self):
        with patch("itsdangerous.timed.TimestampSigner.get_timestamp", return_value=int(time.time()) - 7200):
            old_token = self.token(self.client.get("/login"))
        self.assert_recoverable(old_token)

    def test_token_from_lost_session_gets_fresh_form(self):
        old_token = self.token(self.client.get("/login"))
        self.client = self.app.test_client()
        self.assert_recoverable(old_token)

    def test_json_requests_keep_structured_rejection(self):
        with patch("routes.core.AuthService.authenticate_user") as auth:
            response = self.client.post("/login", json={"username": "csrf-test"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "csrf_failed")
        self.assertIn("request_id", response.get_json())
        auth.assert_not_called()

    def test_https_form_allows_same_origin_referrer_and_preserves_csrf_checks(self):
        origin = "https://proxy.example"
        response = self.client.get("/login", base_url=origin)
        self.assertEqual(response.headers["Referrer-Policy"], "same-origin")
        self.assertTrue(self.app.config["WTF_CSRF_SSL_STRICT"])
        data = {
            "username": "csrf-test", "api_key": "synthetic-key",
            "csrf_token": self.token(response),
        }
        with patch("routes.core.AuthService.authenticate_user", return_value=False) as auth:
            for headers in ({}, {"Referer": "https://other.example/login"}):
                rejected = self.client.post("/login", base_url=origin, data=data, headers=headers)
                self.assertEqual(rejected.status_code, 400)
                auth.assert_not_called()
            accepted = self.client.post(
                "/login", base_url=origin, data=data,
                headers={"Referer": origin + "/login"},
            )
        self.assertEqual(accepted.status_code, 401)
        auth.assert_called_once_with("csrf-test", "synthetic-key")
