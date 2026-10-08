"""Bounded, content-free operator scrape and API identity checks."""
import os
from unittest.mock import Mock, patch

from tests.unified_api_test_case import UnifiedApiTestCase
from services.prometheus_export import Exposition, escape_label, render_metrics

PATH = "/v1/metrics/prometheus"
ADMIN = {"Authorization": "Bearer admin-test-key"}


def stats(**changes):
    return {"total_requests": 9, "status_code_breakdown": {"2xx": 3, "3xx": 1, "4xx": 2, "5xx": 2, "other": 1},
            "p50_response_time": 250, "p95_response_time": 1500, "top_provider": "private-provider",
            "prompt": "private-prompt", "api_key_prefix": "private-key", **changes}


class PrometheusTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        self.enabled = patch.dict(os.environ, {"PROMETHEUS_ENABLED": "true"})
        self.enabled.start()
        self.metrics = Mock()
        self.metrics.get_stats.return_value = stats()
        self.service = patch("routes.core.MetricsService.get_instance", return_value=self.metrics)
        self.service.start()

    def tearDown(self):
        self.service.stop()
        self.enabled.stop()
        super().tearDown()

    def test_disabled_gate_precedes_auth_and_methods(self):
        for flag in ("false", "invalid", ""):
            with patch.dict(os.environ, {"PROMETHEUS_ENABLED": flag}):
                for method in ("GET", "HEAD", "POST"):
                    self.assertEqual(self.client.open(PATH, method=method).status_code, 404)
                self.assertLess(self.client.options(PATH).status_code, 300)
        self.metrics.get_stats.assert_not_called()

    def test_api_auth_and_both_admin_checks(self):
        denied = self.client.get(PATH)
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(denied.headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.get(PATH, headers={"Authorization": "Bearer invalid"}).status_code, 401)
        login = self.client.post("/login", data={"username": "admin", "api_key": "admin-test-key"})
        self.assertEqual(login.status_code, 302)
        with self.client.session_transaction() as browser:
            self.assertTrue(browser["authenticated"])
            self.assertTrue(browser["user"]["is_admin"])
        self.assertEqual(self.client.get(PATH).status_code, 401)
        for admin, scopes in ((False, ["chat"]), (False, ["admin"]), (True, ["chat"]), (True, [])):
            with patch("route_helpers.AuthService.verify_api_key", return_value={
                "username": "synthetic", "is_admin": admin, "scopes": scopes,
            }):
                self.assertEqual(self.client.get(PATH, headers=ADMIN).status_code, 403)
        self.metrics.get_stats.assert_not_called()

    def test_gauge_values_units_headers_and_private_field_exclusion(self):
        response = self.client.get(PATH, headers=ADMIN)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "text/plain; version=0.0.4; charset=utf-8")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.metrics.get_stats.assert_called_once_with(hours=24)
        body = response.get_data(as_text=True)
        self.assertIn('# TYPE multillm_requests_window gauge', body)
        self.assertIn('multillm_requests_window{window="24h",status_class="2xx"} 3', body)
        self.assertIn('multillm_latency_window_seconds{window="24h",quantile="0.50"} 0.25', body)
        self.assertIn('multillm_latency_window_seconds{window="24h",quantile="0.95"} 1.5', body)
        self.assertIn('multillm_observed_requests_window{window="24h",source="flask_ledger"} 9', body)
        for private in ("private-provider", "private-prompt", "private-key", "admin-test-key", "counter", "histogram", "ttft", "cost"):
            self.assertNotIn(private, body)

    def test_enabled_method_rejection_and_options(self):
        self.app.config["WTF_CSRF_ENABLED"] = True
        for method in ("POST", "HEAD", "PUT", "DELETE"):
            response = self.client.open(PATH, method=method, headers=ADMIN)
            self.assertEqual(response.status_code, 405)
            self.assertEqual(response.headers["Allow"], "GET, OPTIONS")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertLess(self.client.options(PATH).status_code, 300)
        self.metrics.get_stats.assert_not_called()

    def test_empty_window_omits_latency(self):
        self.metrics.get_stats.return_value = stats(total_requests=0)
        body = self.client.get(PATH, headers=ADMIN).get_data(as_text=True)
        self.assertNotIn("multillm_latency_window_seconds", body)
        self.assertIn('source="flask_ledger"} 0', body)

    def test_pure_serializer_rejects_nonfinite_and_bounds_output(self):
        self.assertEqual(escape_label('a\\b"c\nd'), 'a\\\\b\\"c\\nd')
        for bad in (float("nan"), float("inf"), -float("inf"), True, "123"):
            body = render_metrics(stats(total_requests=bad, p50_response_time=bad,
                                        status_code_breakdown={"2xx": bad}))
            self.assertNotIn("NaN", body)
            self.assertNotIn("nan", body)
            self.assertNotIn("inf", body)
            self.assertNotIn('status_class="2xx"}', body)
            self.assertNotIn('quantile="0.50"}', body)
        body = render_metrics(stats(status_code_breakdown={str(i): i for i in range(10000)}))
        self.assertEqual(body, render_metrics(stats(status_code_breakdown={str(i): i for i in range(10000)})))
        self.assertLessEqual(len(body.encode()), 256 * 1024)
        self.assertLessEqual(len([line for line in body.splitlines() if not line.startswith("#")]), 512)
        self.assertIn("multillm_prometheus_truncated 0", body)

    def test_exposition_reserves_truncation_gauge_at_series_and_byte_limits(self):
        for labels in ({"name": "short"}, {"name": "漢" * 2000}):
            output = Exposition()
            for index in range(1000):
                output.add("bounded", "Bounded test gauge.", index, {**labels, "index": str(index)})
            body = output.finish()
            self.assertLessEqual(len(body.encode()), 256 * 1024)
            self.assertLessEqual(len([line for line in body.splitlines() if not line.startswith("#")]), 512)
            self.assertIn("multillm_prometheus_truncated 1", body)
