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
        invalid = {**CALL, "function": {"name": "lookup", "arguments": '{"q":4}'}}
        with self.requests(
            return_value=upstream(completion(None, calls=[invalid]))
        ) as send:
            response = self.post(tools=[TOOL], routing={"max_escalations": 0})
        assert response.status_code == 502 and send.call_count == 1
        assert response.json["error"]["code"] == "output_validation_failed"
        assert response.json["usage"]["total_tokens"] == 6

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
            assert time.monotonic() - started < 0.2
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
            model["availability"] == "unverified" and "tools" in model["capabilities"]
        )
