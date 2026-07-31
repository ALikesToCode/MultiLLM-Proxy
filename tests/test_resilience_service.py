import os
import unittest
from unittest.mock import patch

from services.resilience_service import ResilienceService


class ResilienceServiceTest(unittest.TestCase):
    def setUp(self):
        ResilienceService.reset()
        self.settings = {
            "CIRCUIT_BREAKER_DEGRADED_FAILURES": "2",
            "CIRCUIT_BREAKER_FAILURES": "3",
            "CIRCUIT_BREAKER_COOLDOWN_SECONDS": "10",
            "CIRCUIT_BREAKER_MAX_COOLDOWN_SECONDS": "60",
            "CIRCUIT_BREAKER_HALF_OPEN_SUCCESSES": "2",
            "CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES": "2",
        }

    def tearDown(self):
        ResilienceService.reset()

    def test_provider_failures_progress_from_closed_to_degraded_to_open(self):
        with patch.dict(os.environ, self.settings, clear=False):
            first = ResilienceService.record_result("openai", 503, now=100)
            second = ResilienceService.record_result("openai", 503, now=101)
            third = ResilienceService.record_result("openai", 503, now=102)
            decision = ResilienceService.before_request("openai", now=103)

        self.assertEqual(first["state"], "closed")
        self.assertEqual(second["state"], "degraded")
        self.assertEqual(third["state"], "open")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "circuit_open")
        self.assertEqual(decision.retry_after, 9)

    def test_rate_limits_are_observed_without_tripping_provider_circuit(self):
        with patch.dict(os.environ, self.settings, clear=False):
            for timestamp in range(100, 110):
                snapshot = ResilienceService.record_result(
                    "openrouter",
                    429,
                    now=timestamp,
                )
            decision = ResilienceService.before_request("openrouter", now=111)

        self.assertEqual(snapshot["state"], "closed")
        self.assertEqual(snapshot["consecutive_failures"], 0)
        self.assertEqual(snapshot["rate_limit_events"], 10)
        self.assertTrue(decision.allowed)

    def test_rate_limited_probe_does_not_count_as_recovery_success(self):
        with patch.dict(os.environ, self.settings, clear=False):
            for timestamp in (100, 101, 102):
                ResilienceService.record_result("openai", 503, now=timestamp)

            first_probe = ResilienceService.before_request("openai", now=113)
            rate_limited = ResilienceService.record_result(
                "openai",
                429,
                now=114,
            )
            second_probe = ResilienceService.before_request("openai", now=115)
            first_success = ResilienceService.record_result(
                "openai",
                200,
                now=116,
            )

        self.assertTrue(first_probe.allowed)
        self.assertEqual(rate_limited["state"], "half_open")
        self.assertTrue(second_probe.allowed)
        self.assertEqual(first_success["state"], "half_open")
        self.assertEqual(first_success["rate_limit_events"], 1)

    def test_half_open_recovery_allows_two_parallel_probes_and_closes(self):
        with patch.dict(os.environ, self.settings, clear=False):
            for timestamp in (100, 101, 102):
                ResilienceService.record_result("openai", 503, now=timestamp)

            first_probe = ResilienceService.before_request("openai", now=113)
            second_probe = ResilienceService.before_request("openai", now=113)
            busy_probe = ResilienceService.before_request("openai", now=113)
            first_success = ResilienceService.record_result(
                "openai",
                200,
                now=114,
            )
            second_success = ResilienceService.record_result(
                "openai",
                200,
                now=115,
            )

        self.assertTrue(first_probe.allowed)
        self.assertEqual(first_probe.state, "half_open")
        self.assertTrue(second_probe.allowed)
        self.assertFalse(busy_probe.allowed)
        self.assertEqual(busy_probe.reason, "circuit_probe_busy")
        self.assertEqual(first_success["state"], "half_open")
        self.assertEqual(second_success["state"], "closed")
        self.assertEqual(second_success["total_successes"], 2)

    def test_failed_recovery_probe_reopens_with_longer_cooldown(self):
        with patch.dict(os.environ, self.settings, clear=False):
            for timestamp in (100, 101, 102):
                ResilienceService.record_result("openai", 503, now=timestamp)
            ResilienceService.before_request("openai", now=113)
            reopened = ResilienceService.record_result("openai", 503, now=114)

        self.assertEqual(reopened["state"], "open")
        self.assertEqual(reopened["retry_after_seconds"], 20)

    def test_late_probe_success_does_not_close_reopened_circuit(self):
        with patch.dict(os.environ, self.settings, clear=False):
            for timestamp in (100, 101, 102):
                ResilienceService.record_result("openai", 503, now=timestamp)
            ResilienceService.before_request("openai", now=113)
            ResilienceService.before_request("openai", now=113)
            failed = ResilienceService.record_result("openai", 503, now=114)
            stale_success = ResilienceService.record_result("openai", 200, now=115)

        self.assertEqual(failed["state"], "open")
        self.assertEqual(stale_success["state"], "open")
        self.assertGreater(stale_success["retry_after_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
