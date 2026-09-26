"""Public status page, free health checks and health-aware automatic routing."""

import json
import os
from unittest.mock import patch

import requests

from services.resilience_service import ResilienceService
from services.route_health import RouteHealth
from tests.unified_api_test_case import UnifiedApiTestCase

ADMIN = {"Authorization": "Bearer admin-test-key"}


class StatusPageTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        RouteHealth.reset()
        ResilienceService.reset()

    def tearDown(self):
        RouteHealth.reset()
        ResilienceService.reset()
        super().tearDown()

    def test_status_json_is_public_cacheable_and_free_of_secrets(self):
        RouteHealth.record("nanogpt:zai-org/glm-5.2:thinking", ok=True, outcome="ok", latency_ms=1200, status=200)

        response = self.client.get("/status.json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "public, max-age=30, s-maxage=60")
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "*")
        self.assertNotIn("Set-Cookie", response.headers)
        status = response.get_json()
        self.assertEqual(status["source"], "live")
        routes = {route["id"]: route for route in status["routes"]}
        glm = routes["auto:glm-5.2"]
        self.assertEqual(glm["status"], "up")
        self.assertEqual(glm["kind"], "chat")
        self.assertEqual(routes["auto:image"]["kind"], "image")
        first = glm["candidates"][0]
        self.assertEqual(first["model"], "nanogpt:zai-org/glm-5.2:thinking")
        self.assertEqual((first["status"], first["success_rate"], first["p50_latency_ms"]), ("up", 1.0, 1200))
        providers = {provider["id"]: provider for provider in status["providers"]}
        self.assertEqual(providers["nanogpt"]["status"], "up")
        body = response.get_data(as_text=True)
        for secret in ("admin-test-key", "opencode-provider-key", "https://", "intelligence.internal"):
            self.assertNotIn(secret, body)
        self.assertNotIn("samples", body)

    def test_status_page_renders_without_login(self):
        RouteHealth.record("opencode:glm-5.2", ok=False, outcome="http_503", status=503)

        response = self.client.get("/status", headers={"Accept": "text/html"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/html")
        self.assertEqual(response.headers["Cache-Control"], "public, max-age=30, s-maxage=60")
        page = response.get_data(as_text=True)
        self.assertIn("<code>auto:glm-5.2</code>", page)
        self.assertIn('<span class="badge badge--down">Down</span>', page)
        self.assertIn("Live figures from the gateway.", page)
        self.assertNotIn("csrf", page.lower())

    def test_open_circuit_marks_a_candidate_down(self):
        with patch.dict(os.environ, {"CIRCUIT_BREAKER_FAILURES": "1"}):
            ResilienceService.record_result("opencode", 503)

        status = self.client.get("/status.json").get_json()

        glm = next(route for route in status["routes"] if route["id"] == "auto:glm-5.2")
        opencode = next(item for item in glm["candidates"] if item["provider"] == "opencode")
        self.assertEqual(opencode["status"], "down")

    def test_health_checks_require_an_admin_key(self):
        self.assertEqual(self.client.post("/v1/health/checks").status_code, 401)

    def test_health_checks_only_list_models_and_record_the_results(self):
        os.environ["NANOGPT_API_KEY"] = "nano-provider-key"
        listed = requests.Response()
        listed.status_code = 200
        listed._content = b'{"data":[]}'
        rejected = requests.Response()
        rejected.status_code = 401
        rejected._content = b'{"error":"invalid key"}'

        def model_list(**kwargs):
            return rejected if kwargs["api_provider"] == "opencode" else listed

        with patch("app.ProxyService.make_request", side_effect=model_list) as make_request:
            response = self.client.post("/v1/health/checks", headers=ADMIN)

        self.assertEqual(response.status_code, 200)
        self.assertEqual({call.kwargs["method"] for call in make_request.call_args_list}, {"GET"})
        self.assertTrue(all(call.kwargs["data"] is None for call in make_request.call_args_list))
        self.assertTrue(all(call.kwargs["url"].endswith("models") for call in make_request.call_args_list))
        results = {item["provider"]: item for item in response.get_json()["results"]}
        self.assertEqual(results["nanogpt"]["result"], "ok")
        self.assertEqual(results["opencode"], {**results["opencode"], "result": "failed", "reason": "http_401"})
        self.assertEqual(results["cloudflare"]["reason"], "no_free_check")
        self.assertFalse(response.get_json()["stored"], "no D1 store in this deployment")
        self.assertNotIn("nano-provider-key", response.get_data(as_text=True))

        status = self.client.get("/status.json").get_json()
        providers = {provider["id"]: provider for provider in status["providers"]}
        self.assertEqual(providers["opencode"]["last_check"], "failed")
        self.assertEqual(providers["opencode"]["status"], "down")
        self.assertEqual(providers["nanogpt"]["status"], "up")
        self.assertIsNotNone(providers["nanogpt"]["last_check_at"])


class HealthOrderedRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        RouteHealth.reset()
        os.environ["AUTO_ROUTE_ORDERING"] = "health"
        os.environ["NANOGPT_API_KEY"] = "nano-provider-key"

    def tearDown(self):
        RouteHealth.reset()
        super().tearDown()

    def test_a_recently_failing_primary_is_tried_after_healthy_candidates(self):
        for _ in range(3):
            RouteHealth.record("nanogpt:zai-org/glm-5.2:thinking", ok=False, outcome="http_503", status=503)

        with (
            patch("routes.unified.NanoGPTKeyPool.select_key", return_value="nano-provider-key"),
            patch("app.ProxyService.make_request", return_value=self._chat_response("open code first")) as make_request,
        ):
            response = self.client.post("/v1/chat/completions", headers=ADMIN, json={
                "model": "auto:glm-5.2", "messages": [{"role": "user", "content": "hi"}]})

        self.assertEqual(response.status_code, 200)
        self.assertEqual([call.kwargs["api_provider"] for call in make_request.call_args_list], ["opencode"])
        self.assertEqual(response.headers["X-MultiLLM-Auto-Ordering"], "health")
        self.assertEqual(response.headers["X-MultiLLM-Auto-Selected-Priority"], "2")
        self.assertEqual(response.headers["X-MultiLLM-Route-Decision"], "auto-health")
        self.assertNotIn("X-MultiLLM-Auto-Failover-Reasons", response.headers)
        recorded = RouteHealth.snapshot("opencode:glm-5.2")
        self.assertEqual(recorded["last_outcome"], "ok")
        self.assertIsNotNone(recorded["ewma_latency_ms"])

    def test_failover_outcomes_feed_the_next_ordering(self):
        failure = requests.Response()
        failure.status_code = 502
        failure._content = json.dumps({"error": {"message": "bad gateway"}}).encode()
        failure.headers["Content-Type"] = "application/json"

        with (
            patch("routes.unified.NanoGPTKeyPool.select_key", return_value="nano-provider-key"),
            patch("app.ProxyService.make_request", side_effect=[failure, self._chat_response()]),
        ):
            first = self.client.post("/v1/chat/completions", headers=ADMIN, json={
                "model": "auto:glm-5.2", "messages": [{"role": "user", "content": "hi"}]})

        self.assertEqual(first.headers["X-MultiLLM-Route-Decision"], "auto-failover")
        nanogpt = RouteHealth.snapshot("nanogpt:zai-org/glm-5.2:thinking")
        self.assertEqual((nanogpt["last_outcome"], nanogpt["last_status"]), ("http_502", 502))
        self.assertEqual(RouteHealth.snapshot("provider:nanogpt")["consecutive_failures"], 1)
