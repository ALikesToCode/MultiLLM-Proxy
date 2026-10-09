import json
import time
from unittest.mock import patch

import requests

from services.control_plane_backup import capture
from tests.intelligence_fixtures import IntelligenceApiTestCase, completion, upstream

TOOL = {
    "type": "function",
    "function": {
        "name": "lookup",
        "parameters": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
            "additionalProperties": False,
        },
    },
}
CALL = {
    "id": "call-1",
    "type": "function",
    "function": {"name": "lookup", "arguments": '{"q":"test"}'},
}


class IntelligenceHttpTests(IntelligenceApiTestCase):
    def test_tools_and_results_survive_payment_failover_with_safe_metadata(self):
        self.seed()
        messages = [
            {"role": "user", "content": "test"},
            {"role": "assistant", "tool_calls": [CALL]},
            {"role": "tool", "tool_call_id": "call-1", "content": "result"},
        ]
        with self.requests(
            side_effect=[
                upstream({"error": "secret upstream prose"}, 402),
                upstream(completion(None, calls=[CALL])),
            ]
        ) as send:
            response = self.post(
                messages=messages,
                tools=[TOOL],
                reasoning_effort="high",
                routing={"version": 1, "source": "jev", "required_capabilities": []},
            )
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["model"] == "navyai:large"
        assert payload["multillm"] == {
            "version": 1,
            "request_id": "omni-request-1",
            "selected_provider": "navyai",
            "selected_model": "navyai:large",
            "attempts": 2,
            "escalations": 0,
            "reason": "availability_fallback",
            "usage_complete": True,
        }
        assert payload["choices"][0]["message"]["tool_calls"] == [CALL]
        for call in send.call_args_list:
            data = json.loads(call.kwargs["data"])
            assert data["messages"] == messages and data["tools"] == [TOOL]
            assert data["reasoning_effort"] == "high" and "routing" not in data
            assert call.kwargs["force_raw_passthrough"] and not call.kwargs["use_cache"]
        assert (
            b"private thoughts" not in response.data
            and b"secret upstream prose" not in response.data
        )

    def test_explicit_selection_and_effort_are_retained_without_fallback(self):
        self.seed()
        with self.requests(
            return_value=upstream({}, 429, {"Retry-After": "17"})
        ) as send:
            response = self.post(
                model="openai:small",
                reasoning_effort="max",
                routing={"max_attempts": 3},
            )
        assert response.status_code == 429 and send.call_count == 1
        assert response.headers["Retry-After"] == "17"
        assert response.json["error"]["code"] == "upstream_rate_limited"
        assert response.json["multillm"]["reason"] == "explicit"
        assert json.loads(send.call_args.kwargs["data"])["reasoning_effort"] == "max"

    def test_retry_after_date_cannot_carry_upstream_prose(self):
        self.seed()
        with self.requests(
            return_value=upstream(
                {}, 429, {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT private-canary"}
            )
        ):
            response = self.post(model="openai:small", routing={})
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "Wed, 21 Oct 2015 07:28:00 GMT"
        assert b"private-canary" not in response.data

    def test_failed_json_escalates_once_and_aggregates_usage(self):
        self.seed()
        with self.requests(
            side_effect=[
                upstream(completion("not json")),
                upstream(completion('{"ok":true}')),
            ]
        ) as send:
            response = self.post(
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "ok",
                        "schema": {
                            "type": "object",
                            "properties": {"ok": {"const": True}},
                            "required": ["ok"],
                        },
                    },
                }
            )
        assert response.status_code == 200 and send.call_count == 2
        assert response.json["usage"] == {
            "prompt_tokens": 8,
            "completion_tokens": 4,
            "total_tokens": 12,
        }
        assert response.json["multillm"]["escalations"] == 1
        assert response.json["multillm"]["reason"] == "quality_escalation"

    def test_quality_limits_and_invalid_tool_arguments(self):
        self.seed()
        invalid = {**CALL, "function": {"name": "lookup", "arguments": '{}'}}
        with self.requests(
            return_value=upstream(completion(None, calls=[invalid]))
        ) as send:
            response = self.post(tools=[TOOL], routing={"max_escalations": 0})
        assert response.status_code == 502 and send.call_count == 1
        assert response.json["error"]["code"] == "output_validation_failed"
        assert response.json["usage"]["total_tokens"] == 6

    def test_a_refusal_before_output_falls_back_and_charges_only_what_was_used(self):
        self.seed()
        refusal = {"error": {"message": "Invalid value for reasoning_effort: synthetic-private-detail"}}
        with self.requests(
            side_effect=[upstream(refusal, 400), upstream(completion())]
        ) as send:
            response = self.post(reasoning_effort="xhigh")
        assert response.status_code == 200 and send.call_count == 2
        assert response.json["multillm"]["reason"] == "availability_fallback"
        assert response.json["multillm"]["usage_complete"] is True
        assert b"synthetic-private-detail" not in response.data
        (row,) = capture()["tables"]["intelligence_reservations"]
        assert row["state"] == "settled" and row["charged"] == 6

    def test_a_pinned_model_refusal_is_not_retried_and_does_not_hold_the_reservation(self):
        self.seed()
        with self.requests(return_value=upstream({}, 422)) as send:
            response = self.post(model="openai:small", routing={})
        assert send.call_count == 1 and response.status_code == 502
        assert response.json["error"]["code"] == "upstream_error"
        (row,) = capture()["tables"]["intelligence_reservations"]
        assert row["state"] == "settled" and row["charged"] == 0

    def test_a_504_still_keeps_the_whole_reservation(self):
        self.seed()
        with self.requests(return_value=upstream({}, 504)) as send:
            response = self.post()
        assert send.call_count == 1 and response.status_code == 502
        (row,) = capture()["tables"]["intelligence_reservations"]
        assert row["state"] == "unknown" and row["charged"] == row["reserved"]

    def test_timeout_and_http_200_errors_are_uncertain_and_never_replayed(self):
        self.seed()
        for effect in (
            requests.Timeout("synthetic-provider-key"),
            upstream({"error": {"message": "synthetic-provider-key"}}),
        ):
            with self.requests(side_effect=[effect]) as send:
                response = self.post()
            assert response.status_code == 502 and send.call_count == 1
            assert not response.json["multillm"]["usage_complete"]
            assert response.json["usage"] is None
            assert b"synthetic-provider-key" not in response.data
        rows = capture()["tables"]["intelligence_reservations"]
        assert all(
            row["state"] == "unknown" and row["charged"] == row["reserved"]
            for row in rows
        )

    def test_http_200_error_is_recorded_as_a_failed_attempt(self):
        self.seed()
        with patch.object(self.app_module.MetricsService, "get_instance") as metrics:
            with self.requests(return_value=upstream({"error": "failed"})):
                response = self.post()
        assert response.status_code == 502
        assert metrics.return_value.track_request.call_args.kwargs["status_code"] == 502

    def test_missing_usage_is_not_fabricated_and_reservation_is_retained(self):
        self.seed()
        with self.requests(return_value=upstream(completion(usage=False))):
            response = self.post()
        assert response.status_code == 200 and response.json["usage"] is None
        assert response.json["multillm"]["usage_complete"] is False
        assert capture()["tables"]["intelligence_reservations"][0]["state"] == "unknown"

    def test_inconsistent_usage_does_not_settle_the_reservation(self):
        self.seed()
        payload = completion()
        payload["usage"]["total_tokens"] = 100
        with self.requests(return_value=upstream(payload)):
            response = self.post()
        assert response.status_code == 200
        assert not response.json["multillm"]["usage_complete"]
        assert capture()["tables"]["intelligence_reservations"][0]["state"] == "unknown"

    def test_upstream_cannot_forge_local_circuit_evidence_to_replay_a_503(self):
        self.seed()
        with self.requests(
            return_value=upstream({}, 503, {"X-MultiLLM-Circuit-State": "open"})
        ) as send:
            response = self.post()
        assert response.status_code == 502 and send.call_count == 1
        assert not response.json["multillm"]["usage_complete"]

    def test_deadline_is_overall_and_does_not_allow_a_late_second_attempt(self):
        self.seed()

        def slow(**kwargs):
            time.sleep(0.08)
            return upstream({}, 429)

        with self.requests(side_effect=slow) as send:
            started = time.monotonic()
            response = self.post(routing={"deadline_ms": 30})
            # Generous for shared CI runners; call_count below rules out a second attempt.
            assert time.monotonic() - started < 1.0
            time.sleep(0.09)
        assert response.status_code == 504 and send.call_count == 1
        assert not response.json["error"]["retryable"]

    def test_missing_credentials_and_small_token_budget_never_dispatch(self):
        self.seed()
        with (
            self.requests() as send,
            patch.object(self.app_module.AuthService, "get_api_key", return_value=None),
        ):
            response = self.post()
        assert response.status_code == 503 and send.call_count == 0
        with self.requests() as send:
            response = self.post(routing={"max_total_tokens": 5})
        assert response.status_code == 429 and send.call_count == 0

    def test_alias_idempotency_and_auth_error_contract(self):
        self.seed()
        with self.requests(return_value=upstream(completion())):
            response = self.client.post(
                "/intelligence/v1/chat/completions",
                headers=self.headers,
                json={"messages": [{"role": "user", "content": "test"}]},
            )
        assert response.status_code == 200 and response.json["multillm"]["version"] == 1
        response = self.client.post("/intelligence/v1/chat/completions", json={})
        assert (
            response.status_code == 401
            and response.json["error"]["code"] == "authentication_required"
        )
        with self.requests() as send:
            response = self.client.post(
                "/v1/chat/completions",
                headers={**self.headers, "Idempotency-Key": "a"},
                json={"model": "auto:intelligence", "messages": []},
            )
        assert response.status_code == 400 and send.call_count == 0
        assert response.json["error"]["code"] == "idempotency_not_supported"

    def test_no_extra_jev_call_and_models_do_not_claim_a_probe(self):
        self.seed()
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post(routing={"source": "jev", "task": "coding"})
            assert response.status_code == 200 and send.call_count == 1
        models = self.client.get("/v1/models", headers=self.headers).json["data"]
        model = next(m for m in models if m["id"] == "auto:intelligence")
        assert (
            model["availability"] == "unverified"
            and "tools" in model["capability_tags"]
            and model["capabilities"]["supports_tools"] is True
        )


SIGNATURE = {"google": {"thought_signature": "c2lnbmVkIHJlYXNvbmluZw=="}}
SIGNED_CALL = {**CALL, "extra_content": SIGNATURE}


class GeminiIntelligenceTests(IntelligenceApiTestCase):
    def seed_gemini(self):
        from services.intelligence_store import IntelligenceStore
        from tests.test_intelligence_policy import candidate, policy

        IntelligenceStore.seed(
            policy(
                candidates=[
                    candidate("gemini:gemini-flash-lite"),
                    candidate("navyai:large", quality_tier=2),
                ]
            )
        )

    def test_gemini_uses_chat_completions_and_returns_only_the_signature(self):
        self.seed_gemini()
        returned = {
            **CALL,
            "extra_content": {
                "google": {"thought_signature": "c2ln", "private": "dropped"},
                "other": "dropped",
            },
        }
        messages = [
            {"role": "user", "content": "test"},
            {"role": "assistant", "tool_calls": [SIGNED_CALL]},
            {"role": "tool", "tool_call_id": "call-1", "content": "result"},
        ]
        with self.requests(return_value=upstream(completion(None, calls=[returned]))) as send:
            response = self.post(messages=messages, tools=[TOOL], reasoning_effort="xhigh")
        assert response.status_code == 200
        assert response.get_json()["choices"][0]["message"]["tool_calls"] == [
            {**CALL, "extra_content": {"google": {"thought_signature": "c2ln"}}}
        ]
        sent = send.call_args.kwargs
        assert sent["url"] == (
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        )
        assert sent["headers"]["Authorization"] == "Bearer synthetic-provider-key"
        data = json.loads(sent["data"])
        assert data["messages"] == messages, "Gemini gets its own signatures back"
        assert data["reasoning_effort"] == "high" and data["model"] == "gemini-flash-lite"

    def test_a_fallback_provider_never_receives_gemini_signatures(self):
        self.seed_gemini()
        messages = [
            {"role": "user", "content": "test"},
            {"role": "assistant", "tool_calls": [SIGNED_CALL]},
            {"role": "tool", "tool_call_id": "call-1", "content": "result"},
        ]
        with self.requests(
            side_effect=[upstream({}, 429), upstream(completion("done"))]
        ) as send:
            response = self.post(messages=messages, tools=[TOOL])
        assert response.status_code == 200
        gemini, navy = (json.loads(call.kwargs["data"]) for call in send.call_args_list)
        assert gemini["messages"][1]["tool_calls"] == [SIGNED_CALL]
        assert navy["messages"][1]["tool_calls"] == [CALL]
        assert messages[1]["tool_calls"] == [SIGNED_CALL], "the caller's request is not mutated"

    def test_gemini_thinking_tokens_settle_the_reservation(self):
        from services.intelligence_store import IntelligenceStore
        from tests.intelligence_fixtures import frames
        from tests.test_intelligence_policy import candidate, policy

        IntelligenceStore.seed(policy(candidates=[candidate("gemini:gemini-3.8-flash")]))
        thinking = {"prompt_tokens": 147, "completion_tokens": 204, "total_tokens": 631}
        body = completion("trend is down")
        body["usage"] = dict(thinking)
        streamed = frames(
            {"choices": [{"index": 0, "delta": {"content": "trend is down"}}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": thinking},
            "[DONE]",
        )
        with self.requests(
            side_effect=[
                upstream(body),
                upstream(headers={"Content-Type": "text/event-stream"}, chunks=streamed),
            ]
        ):
            plain = self.post(reasoning_effort="high")
            stream = self.post(reasoning_effort="high", stream=True)
        assert plain.status_code == 200 and stream.status_code == 200
        assert plain.json["usage"] == {
            "prompt_tokens": 147, "completion_tokens": 484, "total_tokens": 631
        }, "thinking tokens count as completion tokens"
        assert plain.json["multillm"]["usage_complete"] is True
        assert b'"total_tokens": 631' in stream.data or b'"total_tokens":631' in stream.data
        rows = capture()["tables"]["intelligence_reservations"]
        assert [(row["state"], row["charged"]) for row in rows] == [("settled", 631)] * 2

    def test_gemini_gets_a_skip_signature_for_another_providers_tool_calls(self):
        from services.intelligence_store import IntelligenceStore
        from services.intelligence_transport import SKIP_THOUGHT_SIGNATURE
        from tests.test_intelligence_policy import candidate, policy

        IntelligenceStore.seed(policy(candidates=[candidate("gemini:gemini-3.8-flash")]))
        second = {**CALL, "id": "call-2"}
        messages = [
            {"role": "user", "content": "test"},
            {"role": "assistant", "tool_calls": [CALL, second]},
            {"role": "tool", "tool_call_id": "call-1", "content": "result"},
            {"role": "tool", "tool_call_id": "call-2", "content": "result"},
            {"role": "assistant", "tool_calls": [SIGNED_CALL]},
            {"role": "tool", "tool_call_id": "call-1", "content": "result"},
        ]
        with self.requests(return_value=upstream(completion("done"))) as send:
            response = self.post(messages=messages, tools=[TOOL], reasoning_effort="minimal")
        assert response.status_code == 200
        data = json.loads(send.call_args.kwargs["data"])
        skip = {"google": {"thought_signature": SKIP_THOUGHT_SIGNATURE}}
        assert data["messages"][1]["tool_calls"] == [{**CALL, "extra_content": skip}, second], (
            "only the first call of an unsigned step is signed, as Gemini itself does"
        )
        assert data["messages"][4]["tool_calls"] == [SIGNED_CALL], "Gemini's own signature stays"
        assert data["reasoning_effort"] == "low", "3.8 Flash has no minimal level"
        assert messages[1]["tool_calls"] == [CALL, second], "the caller's request is not mutated"

    def test_sol_thinks_at_low_instead_of_minimal(self):
        from services.intelligence_store import IntelligenceStore
        from tests.test_intelligence_policy import candidate, policy

        IntelligenceStore.seed(
            policy(
                candidates=[
                    candidate("ce-gpt-pro:gpt-6.1-sol"),
                    candidate("ce-gpt-plus:gpt-6-luna"),
                ]
            )
        )
        sent = []
        for model in ("ce-gpt-pro:gpt-6.1-sol", "ce-gpt-plus:gpt-6-luna"):
            for effort in ("minimal", "high"):
                with self.requests(return_value=upstream(completion())) as send:
                    response = self.post(
                        model=model,
                        reasoning_effort=effort,
                        routing={"version": 1, "source": "explicit"},
                    )
                assert response.status_code == 200
                sent.append(json.loads(send.call_args.kwargs["data"])["reasoning_effort"])
        # Codex Everywhere's Pro pool refuses minimal for Sol; Luna accepts it.
        assert sent == ["low", "high", "minimal", "high"]

    def test_a_photo_reserves_the_media_ceiling_instead_of_its_bytes(self):
        from services.intelligence_store import IntelligenceStore
        from tests.test_intelligence_policy import candidate, policy

        IntelligenceStore.seed(
            policy(
                candidates=[
                    candidate("openai:text-only"),
                    candidate(
                        "gemini:gemini-3.8-flash",
                        capabilities=["tools", "json", "streaming", "reasoning", "vision"],
                        context_window=1048576,
                        media_input_tokens=16384,
                    ),
                ]
            )
        )
        photo = "data:image/jpeg;base64," + "A" * 400_000
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Estimate this meal."},
                    {"type": "image_url", "image_url": {"url": photo}},
                ],
            }
        ]
        with self.requests(return_value=upstream(completion("about 650 kcal"))) as send:
            response = self.post(
                messages=messages,
                max_tokens=1024,
                routing={"version": 1, "max_total_tokens": 24000},
            )
        assert response.status_code == 200, response.json
        assert response.json["multillm"]["selected_model"] == "gemini:gemini-3.8-flash"
        data = json.loads(send.call_args.kwargs["data"])
        assert data["messages"][0]["content"][1]["image_url"]["url"] == photo, "the photo is sent whole"
        # Without room for the media ceiling the photo is refused before dispatch.
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post(
                messages=messages,
                max_tokens=1024,
                routing={"version": 1, "max_total_tokens": 16000},
            )
        assert response.status_code == 429 and not send.called

    def test_usage_events_name_the_model_that_answered(self):
        import os

        from services import usage_ledger
        from tests.intelligence_fixtures import frames

        os.environ.update(
            {
                "USAGE_LEDGER_ENABLED": "true",
                "USAGE_LEDGER_BACKEND": "sql",
                "USAGE_LEDGER_FLUSH_SECONDS": "300",
                "USAGE_DB_PATH": os.path.join(self.temp_dir.name, "usage.sqlite3"),
            }
        )
        usage_ledger.LEDGER.reset()
        self.addCleanup(usage_ledger.LEDGER.reset)
        self.seed()
        streamed = frames(
            {"choices": [{"index": 0, "delta": {"content": "ok"}}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
             "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}},
            "[DONE]",
        )
        with self.requests(
            side_effect=[
                upstream(completion()),
                upstream(headers={"Content-Type": "text/event-stream"}, chunks=streamed),
            ]
        ):
            plain = self.post()
            stream = self.post(stream=True)
            assert plain.status_code == 200 and stream.status_code == 200
            stream.get_data()
            stream.close()
        assert usage_ledger.LEDGER.flush(timeout=5)
        rows = usage_ledger.LEDGER.store().recent("2000-01-01T00:00:00.000Z", None, None, 10)
        assert sorted((row["requested_model"], row["selected_model"]) for row in rows) == [
            ("auto:intelligence", "openai:small")
        ] * 2
