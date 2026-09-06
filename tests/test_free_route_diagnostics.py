import unittest
from unittest.mock import patch

import requests
from flask import Response

from services.free_model_policy import FreeCandidate
from services.free_quota_service import FreeQuotaService
from services.free_route_diagnostics import exhausted_details
from tests.test_free_json_responses import FORMAT
from tests.test_free_quota_responses import completion_stream
from tests.unified_api_test_case import UnifiedApiTestCase


class FreeDiagnosticRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.keys = {"groq": "test-groq", "openrouter": "test-router"}
        self.app.config.update(
            FREE_ROUTE_FREE_TIER_PROVIDERS="groq",
            FREE_ROUTE_PROVIDER_ORDER="groq,openrouter",
        )
        for mocked in (
            patch("services.free_model_policy.build_model_catalog", return_value=[]),
            patch.object(
                self.app_module.AuthService, "get_api_key", side_effect=self.keys.get
            ),
        ):
            mocked.start()
            self.addCleanup(mocked.stop)

    def post(self, stream=False):
        return self.client.post(
            "/v1/chat/completions",
            headers={
                "Authorization": "Bearer admin-test-key",
                "Origin": "https://example.test",
            },
            json={
                "model": "free:vision",
                "messages": [{"role": "user", "content": "Return a color"}],
                "response_format": FORMAT,
                "stream": stream,
            },
        )

    def test_quota_and_unsupported_schema_report_independent_failures(self):
        with patch(
            "app.ProxyService.make_request",
            side_effect=[
                Response(
                    "private quota details", status=429, headers={"Retry-After": "42"}
                ),
                Response("private route details", status=404),
            ],
        ) as send:
            response = self.post()
        body = response.get_json()["error"]
        self.assertEqual(response.status_code, 503)
        self.assertEqual(body["code"], "free_providers_failed")
        self.assertEqual(body["attempts"], 2)
        self.assertTrue(body["retryable"])
        self.assertGreaterEqual(int(response.headers["Retry-After"]), 40)
        self.assertEqual(body["retry_after"], int(response.headers["Retry-After"]))
        self.assertEqual(
            [row["reason"] for row in body["failures"]],
            ["rate_limited", "unsupported_parameters"],
        )
        self.assertEqual(
            [row["upstream_status"] for row in body["failures"]], [429, 404]
        )
        self.assertEqual(send.call_count, 2)
        self.assertEqual(
            response.headers["Access-Control-Allow-Origin"], "https://example.test"
        )
        for private in (
            "private quota",
            "private route",
            "test-groq",
            "test-router",
            "Return a color",
        ):
            self.assertNotIn(private, response.get_data(as_text=True))

    def test_incompatible_only_pool_does_not_recommend_automatic_retry(self):
        self.keys.pop("groq")
        with patch("app.ProxyService.make_request", return_value=Response(status=404)):
            response = self.post()
        error = response.get_json()["error"]
        self.assertFalse(error["retryable"])
        self.assertIsNone(error["retry_after"])
        self.assertNotIn("Retry-After", response.headers)
        self.assertEqual(error["failures"][0]["reason"], "unsupported_parameters")

    def assert_wrong_fields_rejected(self, stream):
        bad = self._chat_response('{"wrong_field":"private-output"}')
        if stream:
            bad = Response(
                completion_stream(['{"wrong_field":"private-output"}']),
                content_type="text/event-stream",
            )
        with patch(
            "app.ProxyService.make_request",
            side_effect=[bad, Response(status=404)],
        ):
            response = self.post(stream=stream)
        error = response.get_json()["error"]
        failure = error["failures"][0]
        self.assertEqual(failure["reason"], "schema_mismatch")
        self.assertEqual(failure["upstream_status"], 200)
        self.assertEqual(failure["status"], 502)
        self.assertNotIn("private-output", response.get_data(as_text=True))

    def test_wrong_fields_are_reported_without_returning_the_output(self):
        self.assert_wrong_fields_rejected(False)

    def test_wrong_fields_in_sse_are_reported_without_returning_the_output(self):
        self.assert_wrong_fields_rejected(True)

    def test_network_timeout_is_not_reported_as_malformed_json(self):
        with patch(
            "app.ProxyService.make_request",
            side_effect=[
                requests.ReadTimeout("private hostname"),
                Response(status=404),
            ],
        ):
            response = self.post()
        failure = response.get_json()["error"]["failures"][0]
        self.assertEqual(failure["reason"], "timeout")
        self.assertIsNone(failure["upstream_status"])
        self.assertNotIn("private hostname", response.get_data(as_text=True))

    def test_existing_cooldown_is_reported_without_new_provider_calls(self):
        for provider in self.keys:
            FreeQuotaService.block(f"provider:{provider}", 80)
        with patch("app.ProxyService.make_request") as send:
            response = self.post()
        body = response.get_json()["error"]
        self.assertEqual(response.status_code, 429)
        self.assertEqual(body["reason"], "all_candidates_cooling")
        self.assertEqual(body["attempts"], 0)
        self.assertEqual(body["failures"], [])
        self.assertEqual(len(body["cooldowns"]), 3)
        send.assert_not_called()


class FreeDiagnosticBudgetTest(unittest.TestCase):
    def test_deadline_and_attempt_limit_are_distinguished(self):
        candidates = [FreeCandidate("p:free", "p", "free", True, "free-labelled")]
        for reason in ("deadline_exceeded", "attempt_limit"):
            with self.subTest(reason=reason):
                status, body = exhausted_details(
                    candidates, [], lambda _: 0, stop_reason=reason
                )
                self.assertEqual(status, 503)
                self.assertEqual(body["code"], "free_attempt_limit")
                self.assertEqual(body["reason"], reason)
                self.assertEqual(body["retry_after"], 5)

    def test_large_cooldown_catalog_is_bounded(self):
        candidates = [
            FreeCandidate(f"p:model-{n}", "p", f"model-{n}", False, "free-labelled")
            for n in range(100)
        ]
        _, body = exhausted_details(
            candidates, [], lambda _: 30, stop_reason="providers_failed"
        )
        self.assertEqual(len(body["cooldowns"]), 16)
        self.assertTrue(body["cooldowns_truncated"])
        self.assertEqual(body["retry_after"], 30)
