import json
import os
import unittest
from unittest.mock import patch

from flask import Flask, g

from services.metrics_service import MetricsService


class MetricsServiceAnalyticsTest(unittest.TestCase):
    def setUp(self):
        self.metrics = MetricsService()
        self.base_time = 1_700_000_000

        self.metrics.track_request("openai", 200, 120, timestamp=self.base_time - 60)
        self.metrics.track_request("openai", 500, 480, timestamp=self.base_time - 120)
        self.metrics.track_request("openrouter", 200, 90, timestamp=self.base_time - 180)
        self.metrics.track_request("openrouter", 429, 310, timestamp=self.base_time - 240)
        self.metrics.track_request("gemini", 200, 210, timestamp=self.base_time - 300)

    def test_get_stats_returns_latency_percentiles_and_traffic_breakdown(self):
        stats = self.metrics.get_stats(hours=24, now=self.base_time)

        self.assertEqual(stats["total_requests"], 5)
        self.assertEqual(stats["successful_requests"], 3)
        self.assertEqual(stats["failed_requests"], 2)
        self.assertEqual(stats["error_rate"], 40.0)
        self.assertEqual(stats["p95_response_time"], 480)
        self.assertEqual(stats["p50_response_time"], 210)
        self.assertEqual(stats["top_provider"], "openai")
        self.assertEqual(stats["status_code_breakdown"]["2xx"], 3)
        self.assertEqual(stats["status_code_breakdown"]["4xx"], 1)
        self.assertEqual(stats["status_code_breakdown"]["5xx"], 1)
        self.assertEqual(len(stats["traffic_series"]), 24)
        self.assertEqual(stats["traffic_series"][-1]["requests"], 5)
        self.assertEqual(stats["traffic_series"][-1]["errors"], 2)

    def test_get_provider_breakdown_sorts_by_request_volume_and_keeps_error_data(self):
        breakdown = self.metrics.get_provider_breakdown(hours=24, now=self.base_time)

        self.assertEqual([item["provider"] for item in breakdown[:2]], ["openai", "openrouter"])
        self.assertEqual(breakdown[0]["requests"], 2)
        self.assertEqual(breakdown[0]["errors"], 1)
        self.assertEqual(breakdown[0]["p95_latency"], 480)
        self.assertEqual(breakdown[1]["error_rate"], 50.0)

    def test_get_recent_failures_returns_newest_errors_first(self):
        failures = self.metrics.get_recent_failures(limit=2, now=self.base_time)

        self.assertEqual(len(failures), 2)
        self.assertEqual(failures[0]["provider"], "openai")
        self.assertEqual(failures[0]["status_code"], 500)
        self.assertEqual(failures[1]["provider"], "openrouter")
        self.assertEqual(failures[1]["status_code"], 429)

    def test_track_request_records_request_metadata_without_prompt_text(self):
        app = Flask(__name__)
        metrics = MetricsService()

        with app.test_request_context(
            "/v1/chat/completions",
            method="POST",
            json={
                "model": "opencode:kimi-k2.5",
                "messages": [{"role": "user", "content": "secret prompt"}],
            },
        ):
            g.request_id = "req_test"
            g.authenticated_user = {
                "username": "alice",
                "api_key_prefix": "mllm_live_alice",
            }
            g.rate_limit = {
                "input_tokens": 12,
                "output_tokens": 6,
                "estimated_tokens": 18,
            }
            metrics.track_request("opencode", 200, 42)

        record = metrics.get_request_records(limit=1)[0]
        self.assertEqual(record["request_id"], "req_test")
        self.assertEqual(record["user_id"], "alice")
        self.assertEqual(record["api_key_prefix"], "mllm_live_alice")
        self.assertEqual(record["model"], "opencode:kimi-k2.5")
        self.assertEqual(record["endpoint"], "/v1/chat/completions")
        self.assertEqual(record["input_tokens"], 12)
        self.assertEqual(record["route_decision"], "explicit")
        self.assertEqual(record["circuit_state"], "closed")
        self.assertNotIn("prompt", record)
        self.assertNotIn("secret prompt", str(record))

    def test_unresolved_unified_route_does_not_fabricate_model_provider(self):
        metrics = MetricsService()
        app = Flask(__name__)
        with app.test_request_context(
            "/v1/chat/completions",
            method="POST",
            json={"model": "gpt-4o"},
        ):
            metrics.track_request("unknown", 400, 5)

        record = metrics.get_request_records(limit=1)[0]

        self.assertEqual(record["model"], "gpt-4o")
        self.assertEqual(record["route_decision"], "unresolved")

    def test_cost_summary_labels_configured_estimates_and_coverage(self):
        pricing = json.dumps(
            {
                "openai:gpt-4.1": {
                    "input": 2,
                    "output": 8,
                }
            }
        )
        metrics = MetricsService()
        with patch.dict(
            os.environ,
            {"MODEL_PRICING_USD_PER_MILLION": pricing},
            clear=False,
        ):
            metrics.track_request(
                "openai",
                200,
                40,
                timestamp=self.base_time - 5,
                model="openai:gpt-4.1",
                input_tokens=1_000,
                output_tokens=500,
            )
            metrics.track_request(
                "groq",
                200,
                20,
                timestamp=self.base_time - 4,
                model="groq:unpriced",
                input_tokens=1_000,
                output_tokens=500,
            )

        summary = metrics.get_cost_summary(now=self.base_time)

        self.assertEqual(summary["basis"], "reservation")
        self.assertEqual(summary["estimated_cost"], 0.006)
        self.assertEqual(summary["priced_requests"], 1)
        self.assertEqual(summary["unpriced_requests"], 1)
        self.assertEqual(summary["coverage_percent"], 50.0)
        self.assertEqual(summary["provider_costs"][0]["provider"], "openai")

    def test_cost_summary_keeps_zero_actual_cost_on_provider_basis(self):
        metrics = MetricsService()
        metrics.track_request(
            "openai",
            200,
            20,
            timestamp=self.base_time - 4,
            model="openai:gpt-4.1",
            actual_cost=0.0,
        )

        summary = metrics.get_cost_summary(now=self.base_time)

        self.assertEqual(summary["basis"], "provider")
        self.assertEqual(summary["actual_cost"], 0.0)
        self.assertEqual(summary["priced_requests"], 1)


if __name__ == "__main__":
    unittest.main()
