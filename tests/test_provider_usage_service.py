import json
import unittest
from unittest.mock import Mock, patch

from flask import Flask

from error_handlers import init_error_handlers


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"Content-Type": "application/json"}
        self.closed = False

    def close(self):
        self.closed = True


class FakeAuthService:
    def __init__(self, keys=None, key_pools=None):
        self.keys = keys or {}
        self.key_pools = key_pools or {}

    def get_api_key(self, provider):
        return self.keys.get(provider)

    def get_api_keys(self, provider):
        return list(self.key_pools.get(provider, ()))

    def provider_credential_env_names(self, provider):
        return ()


class FakeMetricsService:
    def get_provider_stats(self, provider):
        return {
            "requests_24h": 3 if provider == "navyai" else 0,
            "success_rate": 100.0 if provider == "navyai" else 0,
            "error_rate": 0,
            "errors": 0,
            "avg_latency": 125.5 if provider == "navyai" else 0,
            "p95_latency": 180.0 if provider == "navyai" else 0,
            "last_request_at": "2026-08-29 10:00:00" if provider == "navyai" else None,
        }

    def get_cost_summary(self):
        return {
            "currency": "USD",
            "provider_costs": [
                {
                    "provider": "navyai",
                    "requests": 3,
                    "estimated_cost": 0.12,
                    "actual_cost": 0,
                    "effective_cost": 0.12,
                }
            ],
        }


class ProviderUsageServiceTest(unittest.TestCase):
    def setUp(self):
        from services.provider_usage_service import ProviderUsageService

        self.ProviderUsageService = ProviderUsageService
        self.config = {
            "API_BASE_URLS": {
                "navyai": "https://api.navy",
                "nanogpt": "https://nano-gpt.com/api/subscription",
                "openrouter": "https://openrouter.ai/api/v1",
                "opencode": "https://opencode.ai/zen/go/v1",
            },
            "NANOGPT_SUBSCRIPTION_BASE_URL": "https://nano-gpt.com/api/subscription",
            "PROVIDER_USAGE_CACHE_TTL_SECONDS": 60,
            "PROVIDER_USAGE_TIMEOUT_SECONDS": 8,
        }

    def build_service(self, auth_service, make_request, monotonic=None):
        proxy_service = Mock()
        proxy_service.make_request.side_effect = make_request
        service = self.ProviderUsageService(
            config=self.config,
            auth_service=auth_service,
            metrics_service=FakeMetricsService(),
            proxy_service=proxy_service,
            monotonic=monotonic,
        )
        return service, proxy_service

    def test_snapshot_normalizes_supported_providers_and_hides_credentials(self):
        auth_service = FakeAuthService(
            keys={
                "navyai": "navy-secret",
                "openrouter": "openrouter-secret",
                "opencode": "opencode-secret",
            },
            key_pools={"nanogpt": ["bad-nano-secret", "good-nano-secret"]},
        )

        def make_request(**kwargs):
            authorization = kwargs["headers"]["Authorization"]
            if kwargs["api_provider"] == "navyai":
                return FakeResponse(
                    200,
                    {
                        "plan": "pro",
                        "limits": {"tokens_per_day": 250000, "rpm": 30},
                        "usage": {
                            "tokens_used_today": 18420,
                            "tokens_remaining_today": 231580,
                            "percent_used": 7.4,
                            "resets_at_utc": "2026-08-30T00:00:00Z",
                            "resets_in_ms": 41523000,
                        },
                        "rate_limits": {
                            "per_minute": {
                                "limit": 30,
                                "used": 4,
                                "remaining": 26,
                                "resets_in_ms": 38120,
                            }
                        },
                        "private_account_field": "must-not-leak",
                    },
                )
            if kwargs["api_provider"] == "nanogpt":
                if authorization == "Bearer bad-nano-secret":
                    return FakeResponse(401, {"error": "bad-nano-secret"})
                return FakeResponse(
                    200,
                    {
                        "active": True,
                        "limits": {"daily": 5000, "monthly": 60000},
                        "daily": {
                            "used": 5,
                            "remaining": 4995,
                            "percentUsed": 0.001,
                            "resetAt": 1788048000000,
                        },
                        "monthly": {
                            "used": 45,
                            "remaining": 59955,
                            "percentUsed": 0.00075,
                            "resetAt": 1790726400000,
                        },
                        "state": "active",
                    },
                )
            if kwargs["api_provider"] == "openrouter":
                return FakeResponse(
                    200,
                    {
                        "data": {
                            "label": "private-key-label",
                            "limit": 10,
                            "usage": 3.25,
                            "limit_remaining": 6.75,
                            "is_free_tier": False,
                        }
                    },
                )
            raise AssertionError(f"Unexpected provider: {kwargs['api_provider']}")

        service, proxy_service = self.build_service(auth_service, make_request)

        payload = service.snapshot(["navyai", "nanogpt", "openrouter", "opencode"])

        providers = {item["provider"]: item for item in payload["providers"]}
        self.assertEqual(providers["navyai"]["status"], "available")
        self.assertEqual(providers["navyai"]["account"]["plan"], "pro")
        self.assertEqual(providers["navyai"]["windows"][0]["unit"], "tokens")
        self.assertEqual(providers["navyai"]["local"]["requests_24h"], 3)
        self.assertEqual(providers["navyai"]["local"]["cost_usd"]["effective"], 0.12)

        self.assertEqual(providers["nanogpt"]["status"], "available")
        self.assertEqual(providers["nanogpt"]["windows"][0]["percent_used"], 0.1)
        self.assertEqual(providers["nanogpt"]["windows"][1]["percent_used"], 0.075)

        self.assertEqual(providers["openrouter"]["status"], "available")
        self.assertEqual(providers["openrouter"]["balances"][0]["remaining"], 6.75)
        self.assertEqual(providers["opencode"]["status"], "unsupported")
        self.assertFalse(providers["opencode"]["supports_authoritative_usage"])

        serialized = json.dumps(payload)
        for secret in (
            "navy-secret",
            "bad-nano-secret",
            "good-nano-secret",
            "openrouter-secret",
            "opencode-secret",
            "must-not-leak",
            "private-key-label",
        ):
            self.assertNotIn(secret, serialized)

        self.assertEqual(proxy_service.make_request.call_count, 4)
        for call in proxy_service.make_request.call_args_list:
            self.assertTrue(call.kwargs["force_raw_passthrough"])
            self.assertFalse(call.kwargs["use_cache"])

    def test_snapshot_caches_authoritative_results_but_refreshes_local_metrics(self):
        current_time = [100.0]
        auth_service = FakeAuthService(keys={"navyai": "navy-secret"})

        def make_request(**kwargs):
            return FakeResponse(200, {"plan": "pro", "usage": {}})

        service, proxy_service = self.build_service(
            auth_service,
            make_request,
            monotonic=lambda: current_time[0],
        )

        first = service.snapshot(["navyai"])
        second = service.snapshot(["navyai"])

        self.assertFalse(first["providers"][0]["source"]["cached"])
        self.assertTrue(second["providers"][0]["source"]["cached"])
        self.assertEqual(proxy_service.make_request.call_count, 1)

        current_time[0] = 161.0
        third = service.snapshot(["navyai"])
        self.assertFalse(third["providers"][0]["source"]["cached"])
        self.assertEqual(proxy_service.make_request.call_count, 2)

    def test_snapshot_isolates_sanitized_provider_failures(self):
        auth_service = FakeAuthService(keys={"navyai": "navy-secret"})

        def make_request(**kwargs):
            return FakeResponse(
                502,
                {"error": "upstream leaked navy-secret and private account data"},
            )

        service, _ = self.build_service(auth_service, make_request)

        payload = service.snapshot(["navyai", "opencode"])

        navyai = payload["providers"][0]
        self.assertEqual(navyai["status"], "error")
        self.assertEqual(navyai["error"]["code"], "upstream_error")
        self.assertEqual(navyai["error"]["status_code"], 502)
        self.assertNotIn("navy-secret", json.dumps(payload))
        self.assertEqual(payload["summary"]["errors"], 1)

    def test_unconfigured_supported_provider_does_not_call_upstream(self):
        service, proxy_service = self.build_service(
            FakeAuthService(),
            lambda **kwargs: self.fail("upstream must not be called"),
        )

        payload = service.snapshot(["navyai"])

        self.assertEqual(payload["providers"][0]["status"], "unconfigured")
        self.assertTrue(payload["providers"][0]["supports_authoritative_usage"])
        proxy_service.make_request.assert_not_called()


class ProviderUsageRouteTest(unittest.TestCase):
    def setUp(self):
        from routes.core import register_core_routes

        self.snapshot = {
            "object": "provider_usage.list",
            "providers": [],
            "summary": {"providers": 0},
        }
        self.usage_service = Mock()
        self.usage_service.snapshot.return_value = self.snapshot
        self.app = Flask(__name__)
        self.app.secret_key = "test-secret"
        self.app.config.update(
            API_BASE_URLS={},
            PROVIDER_USAGE_CACHE_TTL_SECONDS=60,
            PROVIDER_USAGE_TIMEOUT_SECONDS=8,
            TESTING=False,
        )
        init_error_handlers(self.app)
        with patch("routes.core.ProviderUsageService", return_value=self.usage_service):
            register_core_routes(self.app)
        self.client = self.app.test_client()

    def test_admin_provider_usage_requires_login(self):
        with patch("services.auth_service.AuthService.is_authenticated", return_value=False):
            response = self.client.get("/admin/providers/usage")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_admin_provider_usage_requires_admin(self):
        with (
            patch("services.auth_service.AuthService.is_authenticated", return_value=True),
            patch(
                "routes.core.AuthService.get_current_user",
                return_value={"username": "regular", "is_admin": False},
            ),
        ):
            response = self.client.get(
                "/admin/providers/usage",
                headers={"Accept": "application/json"},
            )

        self.assertEqual(response.status_code, 403)
        self.usage_service.snapshot.assert_not_called()

    def test_admin_provider_usage_returns_private_snapshot(self):
        with (
            patch("services.auth_service.AuthService.is_authenticated", return_value=True),
            patch(
                "routes.core.AuthService.get_current_user",
                return_value={"username": "admin", "is_admin": True},
            ),
        ):
            response = self.client.get("/admin/providers/usage")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), self.snapshot)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Pragma"], "no-cache")
        self.usage_service.snapshot.assert_called_once()


if __name__ == "__main__":
    unittest.main()
