import unittest
from unittest.mock import patch

from flask import Flask, Response

from route_helpers import (
    api_auth_required,
    apply_cors_headers,
    build_cors_preflight_response,
    extract_bearer_token,
    is_cors_origin_allowed,
    mask_authorization_header,
    mask_secret,
    parse_allowed_origins,
)
from services.rate_limit_service import LimitDecision


class RouteHelperSecretMaskingTest(unittest.TestCase):
    def test_mask_secret_keeps_only_short_prefix_and_suffix(self):
        self.assertEqual(mask_secret("sk-1234567890abcdef"), "sk-1...cdef")

    def test_mask_secret_redacts_short_values(self):
        self.assertEqual(mask_secret("short"), "<redacted>")

    def test_mask_authorization_header_preserves_scheme_without_token_leak(self):
        masked = mask_authorization_header("Bearer sk-1234567890abcdef")

        self.assertEqual(masked, "Bearer sk-1...cdef")
        self.assertNotIn("1234567890ab", masked)

    def test_extract_bearer_token_accepts_case_insensitive_scheme(self):
        self.assertEqual(extract_bearer_token("bearer token-value"), "token-value")

    def test_extract_bearer_token_rejects_missing_or_wrong_scheme(self):
        self.assertIsNone(extract_bearer_token(None))
        self.assertIsNone(extract_bearer_token("Basic token-value"))
        self.assertIsNone(extract_bearer_token("Bearer "))


class RouteHelperCorsTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_parse_allowed_origins_trims_values(self):
        self.assertEqual(
            parse_allowed_origins(" https://one.example,https://two.example/ "),
            {"https://one.example", "https://two.example"},
        )

    def test_allowed_origin_gets_cors_headers(self):
        with patch.dict("os.environ", {"ALLOWED_ORIGINS": "https://allowed.example"}, clear=False):
            with self.app.test_request_context(
                "/openai/chat/completions",
                headers={"Origin": "https://allowed.example"},
            ):
                response = apply_cors_headers(Response(status=200))

        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://allowed.example")
        self.assertEqual(response.headers["Vary"], "Origin")

    def test_denied_origin_gets_no_cors_headers(self):
        with patch.dict("os.environ", {"ALLOWED_ORIGINS": "https://allowed.example"}, clear=False):
            with self.app.test_request_context(
                "/openai/chat/completions",
                headers={"Origin": "https://evil.example"},
            ):
                response = apply_cors_headers(Response(status=200))

        self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertEqual(response.headers["Vary"], "Origin")

    def test_denied_preflight_returns_403(self):
        with patch.dict("os.environ", {"ALLOWED_ORIGINS": "https://allowed.example"}, clear=False):
            with self.app.test_request_context(
                "/openai/chat/completions",
                method="OPTIONS",
                headers={"Origin": "https://evil.example"},
            ):
                response = build_cors_preflight_response()

        self.assertEqual(response.status_code, 403)
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_development_allows_localhost_when_unconfigured(self):
        with patch.dict("os.environ", {"FLASK_ENV": "development", "ALLOWED_ORIGINS": ""}, clear=False):
            self.assertTrue(is_cors_origin_allowed("http://localhost:5173"))
            self.assertTrue(is_cors_origin_allowed("http://127.0.0.1:3000"))
            self.assertFalse(is_cors_origin_allowed("https://evil.example"))

    def test_no_origin_server_to_server_requests_are_not_cors_responses(self):
        with patch.dict("os.environ", {"ALLOWED_ORIGINS": "https://allowed.example"}, clear=False):
            with self.app.test_request_context("/openai/chat/completions"):
                response = apply_cors_headers(Response(status=200))

        self.assertNotIn("Access-Control-Allow-Origin", response.headers)


class RouteHelperRateLimitTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

        @self.app.route("/openai/chat/completions", methods=["POST"])
        @api_auth_required
        def protected_route():
            return {"ok": True}

    def test_api_auth_required_enforces_rate_limit_before_handler(self):
        with patch(
            "route_helpers.AuthService.verify_api_key",
            return_value={
                "username": "alice",
                "api_key_prefix": "mllm_live_alice",
                "scopes": ["chat"],
            },
        ), patch(
            "route_helpers.RateLimitService.enforce_request",
            return_value=LimitDecision(
                allowed=False,
                status_code=429,
                error="rate_limit_exceeded",
                message="Request-per-minute limit exceeded.",
                retry_after=60,
            ),
        ) as enforce_request:
            response = self.app.test_client().post(
                "/openai/chat/completions",
                headers={"Authorization": "Bearer user-key"},
                json={"messages": [{"role": "user", "content": "hello"}]},
            )

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.get_json()["error"], "rate_limit_exceeded")
        self.assertEqual(response.headers["Retry-After"], "60")
        enforce_request.assert_called_once()
        self.assertEqual(enforce_request.call_args.kwargs["provider"], "openai")


if __name__ == "__main__":
    unittest.main()
