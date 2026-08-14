import json
import os
import unittest
from unittest.mock import patch

import requests
from flask import Flask, Response, g

from route_helpers import (
    api_authenticate_only,
    api_auth_required,
    apply_cors_headers,
    apply_operational_headers,
    build_cors_preflight_response,
    copy_upstream_response_headers,
    extract_bearer_token,
    mask_authorization_header,
    mask_secret,
    provider_from_request_path,
    request_api_key,
    stream_upstream_response,
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

    def test_dedicated_proxy_header_takes_priority_over_upstream_bearer(self):
        app = Flask(__name__)
        with app.test_request_context(
            "/navyai/v1/oauth/me",
            headers={
                "X-MultiLLM-Api-Key": "proxy-admin-key",
                "Authorization": "Bearer navy-oat-user-token",
            },
        ):
            self.assertEqual(request_api_key(), "proxy-admin-key")

    def test_native_api_key_auth_is_available_for_anthropic_gateways(self):
        app = Flask(__name__)
        for path in ("/linkapi/v1/messages", "/nanogpt/v1/messages", "/navyai/v1/messages"):
            with self.subTest(path=path), app.test_request_context(
                path,
                headers={"X-Api-Key": "proxy-admin-key"},
            ):
                self.assertEqual(request_api_key(), "proxy-admin-key")

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

    def test_stream_upstream_response_handles_local_transport_error_body(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 500
        upstream_response._content = b'{"error":{"type":"request_error"}}'
        upstream_response.headers["Content-Type"] = "application/json"

        response = stream_upstream_response(upstream_response)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_data(), upstream_response.content)

    def test_linkapi_response_headers_use_explicit_safe_allowlist(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 429
        upstream_response._content = b'{"error":"rate limited"}'
        upstream_response.headers.update(
            {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "ETag": '"response-tag"',
                "Retry-After": "30",
                "X-Should-Retry": "false",
                "Request-ID": "req_native",
                "X-Request-ID": "req_proxy",
                "X-RateLimit-Remaining-Requests": "0",
                "Anthropic-RateLimit-Requests-Reset": "2026-07-10T10:00:00Z",
                "WWW-Authenticate": "L402 challenge",
                "X-PAYMENT-RESPONSE": "receipt",
                "X-Poll-After": "2",
                "X-NanoGPT-Advisor-ID": "advisor_123",
                "Set-Cookie": "session=upstream-secret; Secure",
                "Location": "https://attacker.example/redirect",
                "Connection": "keep-alive",
                "Content-Encoding": "gzip",
                "Content-Length": "999",
                "X-Unrelated-Upstream": "drop-me",
            }
        )

        response = stream_upstream_response(upstream_response)

        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["ETag"], '"response-tag"')
        self.assertEqual(response.headers["Retry-After"], "30")
        self.assertEqual(response.headers["X-Should-Retry"], "false")
        self.assertEqual(response.headers["Request-ID"], "req_native")
        self.assertEqual(response.headers["X-Request-ID"], "req_proxy")
        self.assertEqual(response.headers["X-RateLimit-Remaining-Requests"], "0")
        self.assertEqual(
            response.headers["Anthropic-RateLimit-Requests-Reset"],
            "2026-07-10T10:00:00Z",
        )
        self.assertEqual(response.headers["WWW-Authenticate"], "L402 challenge")
        self.assertEqual(response.headers["X-PAYMENT-RESPONSE"], "receipt")
        self.assertEqual(response.headers["X-Poll-After"], "2")
        self.assertEqual(response.headers["X-NanoGPT-Advisor-ID"], "advisor_123")
        for header_name in (
            "Set-Cookie",
            "Location",
            "Connection",
            "Content-Encoding",
            "Content-Length",
            "X-Unrelated-Upstream",
        ):
            self.assertNotIn(header_name, response.headers)

    def test_stream_upstream_response_closes_once_when_closed_before_iteration(self):
        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response._content = b"native response"
        upstream_response.headers["Content-Type"] = "application/octet-stream"

        with patch.object(upstream_response, "close") as close:
            response = stream_upstream_response(upstream_response)
            response.close()
            response.close()

        close.assert_called_once()

    def test_stream_upstream_response_closes_once_after_iteration_and_response_close(self):
        import io

        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response.raw = io.BytesIO(b"native response")
        upstream_response.headers["Content-Type"] = "application/octet-stream"

        with patch.object(upstream_response, "close") as close:
            response = stream_upstream_response(upstream_response)
            self.assertEqual(response.get_data(), b"native response")
            response.close()

        close.assert_called_once()

    def test_stream_upstream_response_yields_available_sse_bytes_before_completion(self):
        class IncrementalSseRaw:
            def __init__(self):
                self.chunks = [b"event: first\ndata: one\n\n", b"event: second\ndata: two\n\n"]
                self.read1_calls = []
                self.completed = False

            def read1(self, amount, decode_content=False):
                self.read1_calls.append((amount, decode_content))
                if self.chunks:
                    return self.chunks.pop(0)
                self.completed = True
                return b""

            def read(self, amount):
                raise AssertionError("SSE must not wait for a filled buffered read")

        upstream_response = requests.Response()
        upstream_response.status_code = 200
        upstream_response.raw = IncrementalSseRaw()
        upstream_response.headers["Content-Type"] = "text/event-stream"

        with patch.object(upstream_response, "close") as close:
            response = stream_upstream_response(upstream_response)
            iterator = iter(response.response)

            self.assertEqual(next(iterator), b"event: first\ndata: one\n\n")
            self.assertFalse(upstream_response.raw.completed)
            self.assertEqual(
                b"".join(iterator),
                b"event: second\ndata: two\n\n",
            )
            response.close()

        self.assertTrue(upstream_response.raw.completed)
        self.assertEqual(
            upstream_response.raw.read1_calls,
            [(64 * 1024, True), (64 * 1024, True), (64 * 1024, True)],
        )
        close.assert_called_once()


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

    def test_linkapi_preflight_default_headers_support_native_sdks(self):
        with self.app.test_request_context(
            "/linkapi/v1/messages",
            method="OPTIONS",
            headers={"Origin": "https://client.example"},
        ):
            response = build_cors_preflight_response()

        allowed_headers = response.headers["Access-Control-Allow-Headers"].lower()
        self.assertIn("x-api-key", allowed_headers)
        self.assertIn("x-goog-api-key", allowed_headers)
        self.assertIn("x-multillm-api-key", allowed_headers)
        self.assertIn("x-payment", allowed_headers)
        self.assertIn("x-x402", allowed_headers)
        self.assertIn("anthropic-version", allowed_headers)

        exposed_headers = response.headers["Access-Control-Expose-Headers"].lower()
        self.assertIn("www-authenticate", exposed_headers)
        self.assertIn("x-payment-response", exposed_headers)
        self.assertIn("x-nanogpt-advisor-id", exposed_headers)

    def test_optimizer_cors_exposes_optimization_metadata_headers(self):
        with self.app.test_request_context(
            "/optimize/v1/chat/completions",
            method="OPTIONS",
            headers={"Origin": "https://client.example"},
        ):
            response = build_cors_preflight_response()

        exposed_headers = response.headers["Access-Control-Expose-Headers"].lower()
        self.assertEqual(
            response.headers["Access-Control-Allow-Origin"],
            "https://client.example",
        )
        self.assertIn("x-multillm-optimization", exposed_headers)
        self.assertIn("x-multillm-estimated-input-after", exposed_headers)
        self.assertIn("x-multillm-optimization-cache-hits", exposed_headers)
        self.assertIn("x-multillm-optimization-cache-misses", exposed_headers)
        self.assertIn("x-multillm-summary", exposed_headers)

    def test_cors_exposes_route_observability_headers(self):
        with self.app.test_request_context(
            "/v1/chat/completions",
            method="OPTIONS",
            headers={"Origin": "https://client.example"},
        ):
            response = build_cors_preflight_response()

        exposed_headers = response.headers["Access-Control-Expose-Headers"].lower()
        for header in (
            "x-multillm-provider",
            "x-multillm-model",
            "x-multillm-route-decision",
            "x-multillm-circuit-state",
            "x-multillm-latency-ms",
            "x-multillm-estimated-cost-usd",
            "x-multillm-cost-basis",
            "x-multillm-prompt-cache",
            "x-multillm-prompt-cache-mode",
            "x-multillm-prompt-cache-estimated-tokens",
        ):
            self.assertIn(header, exposed_headers)


class RouteHelperOperationalHeaderTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_explicit_route_headers_include_safe_provider_model_and_cost(self):
        pricing = json.dumps(
            {
                "openai:gpt-4.1": {
                    "input": 2,
                    "output": 8,
                }
            }
        )
        with patch.dict(
            os.environ,
            {"MODEL_PRICING_USD_PER_MILLION": pricing},
            clear=False,
        ), self.app.test_request_context(
            "/v1/chat/completions",
            method="POST",
            json={"model": "openai:gpt-4.1"},
        ):
            g.authenticated_user = {
                "username": "alice",
                "api_key_prefix": "mllm_live_alice",
            }
            g.request_started_at = 1.0
            g.rate_limit = {
                "input_tokens": 1_000,
                "output_tokens": 500,
            }
            with patch("route_helpers.time.perf_counter", return_value=1.125):
                response = apply_operational_headers(Response(status=200))

        self.assertEqual(response.headers["X-MultiLLM-Provider"], "openai")
        self.assertEqual(
            response.headers["X-MultiLLM-Model"],
            "openai:gpt-4.1",
        )
        self.assertEqual(
            response.headers["X-MultiLLM-Route-Decision"],
            "explicit",
        )
        self.assertEqual(
            response.headers["X-MultiLLM-Circuit-State"],
            "closed",
        )
        self.assertEqual(response.headers["X-MultiLLM-Latency-Ms"], "125")
        self.assertEqual(
            response.headers["X-MultiLLM-Estimated-Cost-USD"],
            "0.006",
        )
        self.assertEqual(
            response.headers["X-MultiLLM-Cost-Basis"],
            "reservation",
        )

    def test_unsafe_model_value_is_not_reflected_in_response_header(self):
        with self.app.test_request_context(
            "/v1/chat/completions",
            method="POST",
            json={"model": "openai:gpt\r\nX-Evil: true"},
        ):
            g.authenticated_user = {
                "username": "alice",
                "api_key_prefix": "mllm_live_alice",
            }
            response = apply_operational_headers(Response(status=200))

        self.assertNotIn("X-MultiLLM-Model", response.headers)

    def test_rejected_body_cannot_replace_original_error_response(self):
        with self.app.test_request_context(
            "/optimize/v1/chat/completions",
            method="POST",
            data=b"{",
            content_type="application/json",
        ), patch(
            "route_helpers.request.get_json",
            side_effect=Exception("body rejected"),
        ):
            g.authenticated_user = {
                "username": "alice",
                "api_key_prefix": "mllm_live_alice",
            }
            response = apply_operational_headers(Response(status=413))

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["X-MultiLLM-Provider"], "optimize")

    def test_unauthenticated_response_does_not_expose_operational_metadata(self):
        pricing = json.dumps(
            {
                "openai:gpt-4.1": {
                    "input": 2,
                    "output": 8,
                }
            }
        )
        with patch.dict(
            os.environ,
            {"MODEL_PRICING_USD_PER_MILLION": pricing},
            clear=False,
        ), self.app.test_request_context(
            "/v1/chat/completions",
            method="POST",
            json={"model": "openai:gpt-4.1"},
        ):
            g.request_started_at = 1.0
            g.rate_limit = {
                "input_tokens": 1_000,
                "output_tokens": 500,
            }
            response = apply_operational_headers(Response(status=401))

        self.assertFalse(
            any(
                name.startswith("X-MultiLLM-")
                for name in response.headers.keys()
            )
        )

    def test_raw_route_reports_passthrough_instead_of_false_closed_circuit(self):
        with self.app.test_request_context(
            "/navyai/v1/chat/completions",
            method="POST",
            json={"model": "glm-5.2"},
        ):
            g.authenticated_user = {
                "username": "alice",
                "api_key_prefix": "mllm_live_alice",
            }
            response = apply_operational_headers(Response(status=200))

        self.assertEqual(
            response.headers["X-MultiLLM-Circuit-State"],
            "passthrough",
        )


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

    def test_authenticate_only_validates_key_without_reserving_rate_limit(self):
        app = Flask(__name__)

        @app.route("/optimize/v1/chat/completions", methods=["POST"])
        @api_authenticate_only
        def optimized_route():
            return {"ok": True}

        auth_service = api_authenticate_only.__globals__["AuthService"]
        rate_limit_service = api_authenticate_only.__globals__["RateLimitService"]
        with patch.object(
            auth_service,
            "verify_api_key",
            return_value={
                "username": "alice",
                "api_key_prefix": "mllm_live_alice",
                "scopes": ["chat"],
            },
        ), patch.object(rate_limit_service, "enforce_request") as enforce_request:
            response = app.test_client().post(
                "/optimize/v1/chat/completions",
                headers={"Authorization": "Bearer user-key"},
                json={"messages": [{"role": "user", "content": "hello"}]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"ok": True})
        enforce_request.assert_not_called()


class LinkAPINativeProxyAuthenticationTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

        @self.app.route("/linkapi/v1/messages", methods=["POST"])
        @api_auth_required
        def protected_route():
            return {"ok": True}

    def test_native_caller_auth_styles_authenticate_the_proxy(self):
        auth_service = api_auth_required.__globals__["AuthService"]
        rate_limit_service = api_auth_required.__globals__["RateLimitService"]
        allowed = LimitDecision(
            allowed=True,
            status_code=200,
            error=None,
            message=None,
        )

        auth_styles = (
            ({"Authorization": "Bearer proxy-admin-key"}, ""),
            ({"X-Api-Key": "proxy-admin-key"}, ""),
            ({"X-Goog-Api-Key": "proxy-admin-key"}, ""),
            ({}, "?key=proxy-admin-key"),
        )
        for headers, query in auth_styles:
            with self.subTest(headers=headers, query=query), patch.object(
                auth_service,
                "verify_api_key",
                return_value={
                    "username": "alice",
                    "api_key_prefix": "mllm_live_alice",
                    "scopes": ["chat"],
                },
            ) as verify_api_key, patch.object(
                rate_limit_service,
                "enforce_request",
                return_value=allowed,
            ):
                response = self.app.test_client().post(
                    f"/linkapi/v1/messages{query}",
                    headers=headers,
                    json={"messages": []},
                )

            self.assertEqual(response.status_code, 200)
            verify_api_key.assert_called_once_with("proxy-admin-key", "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
