import unittest
from unittest.mock import patch

from flask import Flask, Response

from route_helpers import (
    api_auth_required,
    apply_cors_headers,
    build_cors_preflight_response,
    copy_upstream_response_headers,
    extract_bearer_token,
    mask_authorization_header,
    mask_secret,
    provider_from_request_path,
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

    def test_copy_upstream_response_headers_drops_hop_by_hop_values(self):
        headers = copy_upstream_response_headers(
            {
                "Content-Type": "application/json",
                "Connection": "keep-alive",
                "Transfer-Encoding": "chunked",
                "X-Request-ID": "req_123",
            }
        )

        self.assertEqual(
            headers,
            {
                "Content-Type": "application/json",
                "X-Request-ID": "req_123",
            },
        )


class RouteHelperCorsTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_any_browser_origin_gets_cors_headers(self):
        with self.app.test_request_context(
            "/openai/chat/completions",
            headers={"Origin": "https://client.example"},
        ):
            response = apply_cors_headers(Response(status=200))

        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://client.example")
        self.assertEqual(response.headers["Vary"], "Origin")

    def test_configured_allowlist_does_not_restrict_api_provider_cors(self):
        with patch.dict("os.environ", {"ALLOWED_ORIGINS": "https://allowed.example"}, clear=False):
            with self.app.test_request_context(
                "/openai/chat/completions",
                headers={"Origin": "https://evil.example"},
            ):
                response = apply_cors_headers(Response(status=200))

        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://evil.example")
        self.assertEqual(response.headers["Vary"], "Origin")

    def test_preflight_allows_any_browser_origin(self):
        with self.app.test_request_context(
            "/openai/chat/completions",
            method="OPTIONS",
            headers={
                "Origin": "https://client.example",
                "Access-Control-Request-Method": "POST",
            },
        ):
            response = build_cors_preflight_response()

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://client.example")

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
        auth_service = api_auth_required.__globals__["AuthService"]
        rate_limit_service = api_auth_required.__globals__["RateLimitService"]
        with patch.object(
            auth_service,
            "verify_api_key",
            return_value={
                "username": "alice",
                "api_key_prefix": "mllm_live_alice",
                "scopes": ["chat"],
            },
        ), patch.object(
            rate_limit_service,
            "enforce_request",
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

    def test_provider_from_v1_plain_model_uses_unified_bucket(self):
        provider = provider_from_request_path(
            "/v1/chat/completions",
            {"model": "gpt-4o"},
        )

        self.assertEqual(provider, "unified")

    def test_provider_from_v1_prefixed_model_uses_real_provider(self):
        provider = provider_from_request_path(
            "/v1/chat/completions",
            {"model": "openrouter:openai/gpt-4o"},
        )

        self.assertEqual(provider, "openrouter")


if __name__ == "__main__":
    unittest.main()
