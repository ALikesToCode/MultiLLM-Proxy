import unittest
from unittest.mock import Mock, patch

from routes.core import build_dashboard_analytics, build_system_metrics


class SystemMetricsTest(unittest.TestCase):
    def test_build_system_metrics_does_not_block_on_cpu_sampling(self):
        metrics_service = Mock(start_time=123.4)

        with patch("routes.core.psutil.cpu_percent", return_value=12.34) as cpu_percent:
            with patch("routes.core.psutil.virtual_memory") as virtual_memory:
                virtual_memory.return_value.percent = 56.78

                payload = build_system_metrics(metrics_service)

        cpu_percent.assert_called_once_with(interval=None)
        self.assertEqual(payload["cpu_usage"], 12.3)
        self.assertEqual(payload["memory_usage"], 56.8)
        self.assertEqual(payload["uptime_start_seconds"], 123)

    def test_dashboard_circuit_counts_exclude_passthrough_providers(self):
        metrics_service = Mock()
        metrics_service.get_stats.return_value = {"traffic_series": []}
        metrics_service.get_provider_breakdown.return_value = []
        metrics_service.get_recent_failures.return_value = []
        metrics_service.get_cost_summary.return_value = {"currency": "USD"}
        providers = {
            "navyai": {"active": True, "is_configured": True},
            "opencode": {"active": True, "is_configured": True},
            "openai": {"active": True, "is_configured": True},
        }

        with patch(
            "routes.core.ResilienceService.snapshot",
            side_effect=lambda provider: {
                "provider": provider,
                "state": "open",
            },
        ):
            analytics = build_dashboard_analytics(metrics_service, providers)

        circuits = {
            circuit["provider"]: circuit
            for circuit in analytics["circuits"]
        }
        self.assertEqual(circuits["navyai"]["mode"], "bypassed")
        self.assertEqual(circuits["opencode"]["mode"], "mixed")
        self.assertEqual(circuits["openai"]["mode"], "managed")
        self.assertEqual(analytics["circuit_counts"]["open"], 2)


if __name__ == "__main__":
    unittest.main()
