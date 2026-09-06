import json
import unittest
from unittest.mock import patch

from flask import Response

from services.free_compatibility import inspect_compatibility
from services.free_quota_service import FreeQuotaService
from tests.test_free_json_responses import FORMAT
from tests.unified_api_test_case import UnifiedApiTestCase


class CompatibilityInspectionTest(unittest.TestCase):
    def test_known_limit_is_recognized_and_bytes_remain_readable(self):
        body = json.dumps({"error": {"message": "Too many images provided. This model supports up to 3 images"}}).encode()
        response, mismatch = inspect_compatibility(Response(iter([body[:20], body[20:]]), status=400))
        self.assertTrue(mismatch)
        self.assertEqual(response.get_data(), body)

    def test_unknown_input_and_policy_errors_are_not_retried(self):
        for message in ("temperature must be a number", "Content policy violation", "Provider returned error"):
            with self.subTest(message=message):
                body = json.dumps({"error": {"message": message}}).encode()
                response, mismatch = inspect_compatibility(Response(body, status=400))
                self.assertFalse(mismatch)
                self.assertEqual(response.get_data(), body)

    def test_oversized_error_is_replayed_without_classification(self):
        body = b"x" * 20000
        response, mismatch = inspect_compatibility(Response(iter([body[:10000], body[10000:]]), status=413))
        self.assertFalse(mismatch)
        self.assertEqual(response.get_data(), body)

    def test_schema_and_context_errors_are_request_specific(self):
        for status, message in ((422, "response_format json_schema is not supported"), (413, "maximum context length exceeded")):
            with self.subTest(status=status):
                _, mismatch = inspect_compatibility(Response(json.dumps({"error": {"message": message}}), status=status))
                self.assertTrue(mismatch)


class ModelSpecificFallbackTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.app.config.update(FREE_ROUTE_PROVIDER_ORDER="groq,openrouter", FREE_ROUTE_FREE_TIER_PROVIDERS="groq")
        for mocked in (
            patch("services.free_model_policy.build_model_catalog", return_value=[]),
            patch.object(self.app_module.AuthService, "get_api_key", side_effect={"groq": "synthetic-key"}.get),
        ):
            mocked.start()
            self.addCleanup(mocked.stop)

    def post(self):
        return self.client.post("/v1/chat/completions", headers={"Authorization": "Bearer admin-test-key"}, json={
            "model": "free:vision", "messages": [{"role": "user", "content": "Return the synthetic color"}], "response_format": FORMAT,
        })

    def test_schema_mismatch_keeps_sibling_model_available(self):
        with patch("app.ProxyService.make_request", side_effect=[self._chat_response('{"wrong":true}'), self._chat_response('{"color":"red"}')]) as send:
            response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(send.call_count, 2)
        self.assertEqual(FreeQuotaService.remaining("provider:groq"), 0)
        self.assertGreater(FreeQuotaService.remaining("model:groq:qwen/qwen3.8-27b"), 0)
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Model"], "groq:qwen/qwen3.6-27b")

    def test_image_limit_fails_over_without_cooling_account_or_model(self):
        error = Response(json.dumps({"error": {"message": "Too many images provided"}}), status=400)
        with patch("app.ProxyService.make_request", side_effect=[error, self._chat_response('{"color":"red"}')]) as send:
            response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(send.call_count, 2)
        self.assertEqual(FreeQuotaService.remaining("provider:groq"), 0)
        self.assertEqual(FreeQuotaService.remaining("model:groq:qwen/qwen3.8-27b"), 0)

    def test_real_quota_still_cools_every_sibling_model(self):
        with patch("app.ProxyService.make_request", return_value=Response(status=429, headers={"Retry-After": "42"})) as send:
            response = self.post()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(send.call_count, 1)
        self.assertGreater(FreeQuotaService.remaining("provider:groq"), 0)

    def test_all_incompatible_reports_no_automatic_retry(self):
        with patch("app.ProxyService.make_request", side_effect=[
            Response(json.dumps({"error": {"message": "Too many images"}}), status=400),
            Response(json.dumps({"error": {"message": "json_schema is not supported"}}), status=422),
        ]):
            response = self.post()
        self.assertEqual(response.status_code, 503)
        error = response.get_json()["error"]
        self.assertFalse(error["retryable"])
        self.assertNotIn("Retry-After", response.headers)
        self.assertEqual([item["upstream_status"] for item in error["failures"]], [400, 422])
