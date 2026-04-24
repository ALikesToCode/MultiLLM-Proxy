import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from services.rate_limit_service import RateLimitService


class RateLimitServiceTest(unittest.TestCase):
    def setUp(self):
        self.original_env = os.environ.copy()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["RATE_LIMIT_DB_PATH"] = os.path.join(self.temp_dir.name, "limits.sqlite3")
        os.environ["RATE_LIMIT_ENABLED"] = "true"

    def tearDown(self):
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_rejects_oversized_request_body(self):
        os.environ["MAX_REQUEST_BYTES"] = "8"

        decision = RateLimitService.enforce_request(
            provider="openai",
            user={"username": "alice", "api_key_prefix": "mllm_live_alice"},
            payload_bytes=b"0123456789",
            payload_json={"messages": [{"role": "user", "content": "hello"}]},
            remote_addr="203.0.113.10",
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 413)
        self.assertEqual(decision.error, "request_too_large")

    def test_rejects_output_token_cap_before_upstream_call(self):
        os.environ["MAX_OUTPUT_TOKENS"] = "5"

        decision = RateLimitService.enforce_request(
            provider="openai",
            user={"username": "alice", "api_key_prefix": "mllm_live_alice"},
            payload_bytes=b"{}",
            payload_json={"messages": [{"role": "user", "content": "hello"}], "max_tokens": 6},
            remote_addr="203.0.113.10",
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 400)
        self.assertEqual(decision.error, "max_output_too_large")

    def test_enforces_request_per_minute_limit_by_user_provider(self):
        os.environ["RATE_LIMIT_RPM"] = "1"
        user = {"username": "alice", "api_key_prefix": "mllm_live_alice"}
        payload = {"messages": [{"role": "user", "content": "hello"}]}

        first = RateLimitService.enforce_request(
            provider="openai",
            user=user,
            payload_bytes=b"{}",
            payload_json=payload,
            remote_addr="203.0.113.10",
        )
        second = RateLimitService.enforce_request(
            provider="openai",
            user=user,
            payload_bytes=b"{}",
            payload_json=payload,
            remote_addr="203.0.113.10",
        )

        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.error, "rate_limit_exceeded")
        self.assertEqual(second.retry_after, 60)

    def test_enforces_token_per_minute_limit(self):
        os.environ["RATE_LIMIT_TPM"] = "5"
        user = {"username": "alice", "api_key_prefix": "mllm_live_alice"}

        decision = RateLimitService.enforce_request(
            provider="openai",
            user=user,
            payload_bytes=b"{}",
            payload_json={
                "messages": [{"role": "user", "content": "01234567890123456789"}],
                "max_tokens": 1,
            },
            remote_addr="203.0.113.10",
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 429)
        self.assertEqual(decision.error, "token_rate_limit_exceeded")

    def test_prunes_old_usage_when_sampled(self):
        with sqlite3.connect(os.environ["RATE_LIMIT_DB_PATH"]) as connection:
            connection.row_factory = sqlite3.Row
            RateLimitService._ensure_storage(connection)
            connection.execute(
                """
                INSERT INTO request_usage (
                    created_at, identity, key_prefix, provider, remote_addr,
                    input_tokens, output_tokens, estimated_tokens, stream
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2026-01-01T00:00:00+00:00",
                    "alice",
                    "mllm_live_alice",
                    "openai",
                    "203.0.113.10",
                    1,
                    0,
                    1,
                    0,
                ),
            )
            connection.commit()

        with patch("services.rate_limit_service.random.random", return_value=0.0):
            decision = RateLimitService.enforce_request(
                provider="openai",
                user={"username": "alice", "api_key_prefix": "mllm_live_alice"},
                payload_bytes=b"{}",
                payload_json={"messages": [{"role": "user", "content": "hello"}]},
                remote_addr="203.0.113.10",
            )

        self.assertTrue(decision.allowed)
        with sqlite3.connect(os.environ["RATE_LIMIT_DB_PATH"]) as connection:
            old_count = connection.execute(
                "SELECT COUNT(*) FROM request_usage WHERE created_at = ?",
                ("2026-01-01T00:00:00+00:00",),
            ).fetchone()[0]

        self.assertEqual(old_count, 0)


if __name__ == "__main__":
    unittest.main()
