import unittest
from unittest.mock import Mock, patch

from routes.core import build_system_metrics


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


if __name__ == "__main__":
    unittest.main()
