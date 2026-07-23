import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
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

    def test_body_size_safety_limit_remains_active_when_rate_limits_are_disabled(self):
        os.environ["RATE_LIMIT_ENABLED"] = "false"
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

    def test_reserved_request_slot_is_finalized_into_one_exact_usage_row(self):
        user = {"username": "alice", "api_key_prefix": "mllm_live_alice"}
        reservation = RateLimitService.reserve_request_slot(
            provider="kimi-code",
            user=user,
            remote_addr="203.0.113.10",
        )
        payload = {
            "messages": [{"role": "user", "content": "0123456789ab"}],
            "max_completion_tokens": 5,
        }

        finalized = RateLimitService.finalize_request_slot(
            reservation_id=reservation.metadata["reservation_id"],
            provider="kimi-code",
            user=user,
            payload_bytes=b"{}",
            payload_json=payload,
            remote_addr="203.0.113.10",
        )

        self.assertTrue(reservation.allowed)
        self.assertTrue(finalized.allowed)
        self.assertEqual(finalized.metadata["input_tokens"], 3)
        self.assertEqual(finalized.metadata["output_tokens"], 5)
        with sqlite3.connect(os.environ["RATE_LIMIT_DB_PATH"]) as connection:
            rows = connection.execute(
                "SELECT provider, input_tokens, output_tokens, estimated_tokens "
                "FROM request_usage"
            ).fetchall()
        self.assertEqual(rows, [("kimi-code", 3, 5, 8)])

    def test_reservation_rejects_impossible_output_before_preprocessing(self):
        os.environ["KIMI_CODE_MAX_OUTPUT_TOKENS"] = "8"

        decision = RateLimitService.reserve_request_slot(
            provider="kimi-code",
            user={"username": "alice", "api_key_prefix": "mllm_live_alice"},
            remote_addr="203.0.113.10",
            payload_json={"max_completion_tokens": 9},
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, "max_output_too_large")

    def test_stale_reservation_rechecks_current_rpm_before_finalizing(self):
        os.environ["KIMI_CODE_RATE_LIMIT_RPM"] = "1"
        user = {"username": "alice", "api_key_prefix": "mllm_live_alice"}
        old_time = datetime(2026, 7, 17, 10, 0, tzinfo=timezone.utc)
        current_time = datetime(2026, 7, 17, 10, 2, tzinfo=timezone.utc)
        reserve_globals = RateLimitService.reserve_request_slot.__func__.__globals__
        with patch.dict(reserve_globals, {"_utcnow": lambda: old_time}):
            reservation = RateLimitService.reserve_request_slot(
                provider="kimi-code",
                user=user,
                remote_addr="203.0.113.10",
            )

        with sqlite3.connect(os.environ["RATE_LIMIT_DB_PATH"]) as connection:
            connection.execute(
                """
                INSERT INTO request_usage (
                    created_at, identity, key_prefix, provider, remote_addr,
                    input_tokens, output_tokens, estimated_tokens, stream
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    current_time.isoformat(),
                    "alice",
                    "mllm_live_alice",
                    "kimi-code",
                    "203.0.113.10",
                    1,
                    0,
                    1,
                    0,
                ),
            )
            connection.commit()

        finalize_globals = RateLimitService.finalize_request_slot.__func__.__globals__
        with patch.dict(finalize_globals, {"_utcnow": lambda: current_time}):
            finalized = RateLimitService.finalize_request_slot(
                reservation_id=reservation.metadata["reservation_id"],
                provider="kimi-code",
                user=user,
                payload_bytes=b"{}",
                payload_json={"messages": [{"role": "user", "content": "hello"}]},
                remote_addr="203.0.113.10",
            )

        self.assertFalse(finalized.allowed)
        self.assertEqual(finalized.error, "rate_limit_exceeded")

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

    def test_mimo_defaults_allow_model_sized_prompt_and_output(self):
        os.environ["RATE_LIMIT_TPM"] = "2000000"
        payload = {
            "messages": [{"role": "user", "content": "a" * ((128000 + 1) * 4)}],
            "max_tokens": 131072,
        }

        decision = RateLimitService.enforce_request(
            provider="mimo",
            user={"username": "alice", "api_key_prefix": "mllm_live_alice"},
            payload_bytes=b"{}",
            payload_json=payload,
            remote_addr="203.0.113.10",
        )

        self.assertTrue(decision.allowed, decision)

    def test_mimo_defaults_allow_long_context_request_bodies(self):
        os.environ["RATE_LIMIT_TPM"] = "2000000"

        decision = RateLimitService.enforce_request(
            provider="mimo",
            user={"username": "alice", "api_key_prefix": "mllm_live_alice"},
            payload_bytes=b"0" * (1024 * 1024 + 1),
            payload_json={"messages": [{"role": "user", "content": "hello"}]},
            remote_addr="203.0.113.10",
        )

        self.assertTrue(decision.allowed, decision)

    def test_media_gateway_defaults_allow_documented_upload_sizes(self):
        class SizedPayload:
            def __init__(self, size):
                self.size = size

            def __len__(self):
                return self.size

        for name in (
            "MAX_REQUEST_BYTES",
            "NANOGPT_MAX_REQUEST_BYTES",
            "NAVYAI_MAX_REQUEST_BYTES",
        ):
            os.environ.pop(name, None)

        nanogpt = RateLimitService.check_request_size(
            "nanogpt",
            SizedPayload(16 * 1024 * 1024),
        )
        navyai = RateLimitService.check_request_size(
            "navyai",
            SizedPayload(25 * 1024 * 1024 + 1024),
        )

        self.assertTrue(nanogpt.allowed)
        self.assertTrue(navyai.allowed)
        self.assertEqual(nanogpt.metadata["max_request_bytes"], 16 * 1024 * 1024)
        self.assertEqual(navyai.metadata["max_request_bytes"], 32 * 1024 * 1024)

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

    def test_estimate_input_tokens_counts_message_text_not_metadata(self):
        payload = {
            "messages": [
                {
                    "role": "system",
                    "name": "large_tool_name_that_should_not_count",
                    "content": "12345678",
                },
                {
                    "role": "user",
                    "tool_call_id": "tool_id_that_should_not_count",
                    "content": [{"type": "text", "text": "abcd"}],
                },
            ],
            "metadata": {"tenant": "metadata_should_not_count"},
        }

        self.assertEqual(RateLimitService.estimate_input_tokens(payload), 3)

    def test_estimate_input_tokens_counts_gemini_parts_text(self):
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": "12345678"},
                        {"inline_data": {"mime_type": "image/png", "data": "base64_should_not_count"}},
                    ],
                }
            ]
        }

        self.assertEqual(RateLimitService.estimate_input_tokens(payload), 2)

    def test_estimate_input_tokens_counts_tool_schemas_and_arguments(self):
        payload = {
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "lookup",
                                "arguments": "{\"query\":\"" + "x" * 200 + "\"}",
                            },
                        }
                    ],
                },
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "description": "y" * 200,
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ],
        }

        self.assertGreater(RateLimitService.estimate_input_tokens(payload), 100)

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
