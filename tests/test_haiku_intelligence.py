import json
from copy import deepcopy
from unittest.mock import patch

from services.intelligence_anthropic import HAIKU_INTELLIGENCE_MODEL
from services.intelligence_store import IntelligenceStore
from tests.intelligence_fixtures import (
    IntelligenceApiTestCase,
    completion,
    upstream,
)
from tests.test_intelligence_policy import candidate, policy


def message(text="ok", **overrides):
    return {
        "id": "msg_haiku",
        "type": "message",
        "role": "assistant",
        "model": "claude-haiku-5-5",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 4, "output_tokens": 2},
        **overrides,
    }


def native_frames(*events):
    return [
        f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
        for event in events
    ]


def native_stream(usage=True, complete=True, final_usage=True, output_tokens=6):
    start = {"id": "msg_haiku", "model": "claude-haiku-5-5"}
    if usage:
        start["usage"] = {
            "input_tokens": 4,
            "output_tokens": 0,
            "cache_read_input_tokens": 2,
            "cache_creation_input_tokens": 3,
        }
    events = [
        {"type": "message_start", "message": start},
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "thinking", "thinking": "private-thought-canary"},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {"type": "text", "text": ""},
        },
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "text_delta", "text": "hello"},
        },
        {"type": "content_block_stop", "index": 1},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn"},
            **(
                {"usage": {"output_tokens": output_tokens}}
                if usage and final_usage
                else {}
            ),
        },
    ]
    if complete:
        events.append({"type": "message_stop"})
    joined = b"".join(native_frames(*events))
    # Transport chunks need not coincide with event boundaries.
    return [joined[index : index + 31] for index in range(0, len(joined), 31)]


class HaikuIntelligenceTests(IntelligenceApiTestCase):
    def seed_haiku(self, **overrides):
        IntelligenceStore.seed(
            policy(
                **{
                    "allow_paid_overage": True,
                    "principal_daily_tokens": 1_048_576,
                    "global_daily_tokens": 1_048_576,
                    "candidates": [
                        candidate(
                            "openai:fallback",
                            quality_tier=5,
                            task_scores={"coding": 99},
                            latency_ms=1,
                            tokens_per_second=1000,
                        ),
                        candidate(
                            HAIKU_INTELLIGENCE_MODEL,
                            billing="payg",
                            context_window=1_000_000,
                        ),
                    ],
                    **overrides,
                }
            )
        )

    def haiku_post(self, **fields):
        routing = {"allow_paid_overage": True, **fields.pop("routing", {})}
        return self.post(routing=routing, **fields)

    def test_primary_haiku_precedes_speed_and_scores_in_every_profile(self):
        self.seed_haiku()
        for profile in ("balanced", "quality", "fast"):
            with (
                self.subTest(profile=profile),
                self.requests(return_value=upstream(message())) as send,
            ):
                response = self.haiku_post(
                    routing={"profile": profile, "task": "coding"}
                )
                assert response.status_code == 200
                assert response.json["model"] == HAIKU_INTELLIGENCE_MODEL
                assert response.json["multillm"]["attempts"] == 1
                body = json.loads(send.call_args.kwargs["data"])
                assert body["model"] == "claude-haiku-5-5"
                assert body["thinking"] == {"type": "adaptive"}
                assert body["output_config"]["effort"] == "max"
                assert "routing" not in body
                assert (
                    send.call_args.kwargs["url"]
                    == "https://api.anthropic.com/v1/messages"
                )
                headers = send.call_args.kwargs["headers"]
                assert headers["X-Api-Key"] == "synthetic-provider-key"
                assert headers["Anthropic-Version"] == "2023-06-01"
                assert not any(key.lower() == "authorization" for key in headers)

    def test_explicit_reasoning_effort_wins_over_maximum_default(self):
        self.seed_haiku()
        for requested, effort in (
            ("none", "low"),
            ("minimal", "low"),
            ("low", "low"),
            ("medium", "medium"),
            ("high", "high"),
            ("xhigh", "xhigh"),
            ("max", "max"),
        ):
            with (
                self.subTest(requested=requested),
                self.requests(return_value=upstream(message())) as send,
            ):
                response = self.haiku_post(
                    reasoning_effort=requested, temperature=0.7, top_p=0.9
                )
                assert response.status_code == 200
                body = json.loads(send.call_args.kwargs["data"])
                assert body["output_config"]["effort"] == effort
                assert body["thinking"]["type"] == (
                    "disabled" if requested == "none" else "adaptive"
                )
                assert not {"temperature", "top_p", "reasoning_effort"} & body.keys()

    def test_paid_haiku_still_requires_both_server_and_caller_opt_in(self):
        self.seed_haiku()
        with self.requests(return_value=upstream(completion())) as send:
            response = self.post()
        assert response.status_code == 200
        assert response.json["model"] == "openai:fallback"
        assert send.call_count == 1

    def test_signed_tool_result_round_trip_preserves_native_assistant_blocks(self):
        self.seed_haiku()
        native_content = [
            {"type": "thinking", "thinking": "", "signature": "opaque-signature"},
            {"type": "redacted_thinking", "data": "opaque-redacted-data"},
            {"type": "tool_use", "id": "toolu_signed", "name": "weather", "input": {}},
        ]
        tools = [{"type": "function", "function": {"name": "weather", "parameters": {"type": "object"}}}]
        with self.requests(return_value=upstream(message(content=native_content, stop_reason="tool_use"))):
            first = self.haiku_post(tools=tools)
        assert first.status_code == 200
        assistant = first.json["choices"][0]["message"]
        messages = [
            {"role": "user", "content": "Weather?"}, assistant,
            {"role": "tool", "tool_call_id": "toolu_signed", "content": "Sunny"},
        ]
        with self.requests(return_value=upstream(message())) as send:
            second = self.haiku_post(messages=messages, tools=tools)
        assert second.status_code == 200 and send.call_count == 1
        body = json.loads(send.call_args.kwargs["data"])
        assert body["messages"][1]["content"] == native_content
        assert body["thinking"] == {"type": "adaptive"}
        assert body["output_config"]["effort"] == "max"

    def test_unconfigured_primary_uses_the_existing_fallback(self):
        self.seed_haiku()
        with (
            patch.object(
                self.app_module.AuthService,
                "get_api_key",
                side_effect=(
                    lambda provider: (
                        None if provider == "anthropic" else "synthetic-provider-key"
                    )
                ),
            ),
            self.requests(return_value=upstream(completion())) as send,
        ):
            response = self.haiku_post()
        assert response.status_code == 200
        assert response.json["model"] == "openai:fallback"
        assert send.call_count == 1

    def test_server_paid_policy_remains_required(self):
        self.seed_haiku(allow_paid_overage=False)
        with self.requests(return_value=upstream(completion())) as send:
            response = self.haiku_post()
        assert response.status_code == 200
        assert response.json["model"] == "openai:fallback"
        assert send.call_count == 1

    def test_definite_refusal_falls_back_once_with_original_chat_payload(self):
        self.seed_haiku()
        messages = [
            {"role": "system", "content": "You are Omni."},
            {"role": "user", "content": "hello"},
        ]
        for status in (401, 402, 403, 404, 429):
            with (
                self.subTest(status=status),
                self.requests(
                    side_effect=[
                        upstream({"error": "private-error-canary"}, status),
                        upstream(completion()),
                    ]
                ) as send,
            ):
                response = self.haiku_post(messages=messages)
                assert response.status_code == 200
                assert response.json["multillm"]["attempts"] == 2
                assert response.json["multillm"]["reason"] == "availability_fallback"
                bodies = [
                    json.loads(call.kwargs["data"]) for call in send.call_args_list
                ]
                assert bodies[0]["system"] == "You are Omni."
                assert bodies[1]["messages"] == messages
                assert (
                    not {"thinking", "output_config", "reasoning_effort"}
                    & bodies[1].keys()
                )

    def test_uncertain_error_never_replays_generation(self):
        self.seed_haiku()
        for native, status in (
            ({}, 500),
            ({"error": {"message": "private-error-canary"}}, 200),
            ({"type": "message", "content": []}, 200),
        ):
            with (
                self.subTest(status=status, native=native),
                self.requests(return_value=upstream(native, status)) as send,
            ):
                response = self.haiku_post()
                assert response.status_code == 502
                assert send.call_count == 1
                assert b"private-error-canary" not in response.data

    def test_streaming_translates_fragmented_events_and_cached_usage(self):
        self.seed_haiku()
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"}, chunks=native_stream()
            )
        ) as send:
            response = self.haiku_post(stream=True)
            data = response.data
        assert response.status_code == 200
        assert b'"content":"hello"' in data
        assert b"private-thought-canary" not in data
        events = [
            json.loads(line[6:])
            for line in data.decode().splitlines()
            if line.startswith("data: ") and line[6:] != "[DONE]"
        ]
        assert events[-1]["usage"]["prompt_tokens"] == 9
        assert events[-1]["usage"]["completion_tokens"] == 6
        assert events[-1]["usage"]["total_tokens"] == 15
        assert events[-1]["multillm"]["usage_complete"] is True
        assert send.call_count == 1

    def test_truncated_stream_is_an_error_without_a_replacement(self):
        self.seed_haiku()
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"},
                chunks=native_stream(complete=False),
            )
        ) as send:
            response = self.haiku_post(stream=True)
            data = response.data
        assert b"stream_interrupted" in data
        assert send.call_count == 1

    def test_native_stream_errors_are_sanitized_without_replacement(self):
        self.seed_haiku()
        chunks = native_frames(
            {"type": "message_start", "message": {"id": "msg_haiku"}},
            {"type": "error", "error": {"message": "private-error-canary"}},
        )
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"}, chunks=chunks
            )
        ) as send:
            response = self.haiku_post(stream=True)
            data = response.data
        assert b"stream_interrupted" in data
        assert b"private-error-canary" not in data
        assert send.call_count == 1

    def test_initial_zero_output_usage_does_not_replace_a_missing_final_count(self):
        self.seed_haiku()
        for fields in (
            {"final_usage": False},
            {"output_tokens": None},
            {"output_tokens": True},
            {"output_tokens": -1},
            {"output_tokens": "6"},
        ):
            with (
                self.subTest(fields=fields),
                self.requests(
                    return_value=upstream(
                        headers={"Content-Type": "text/event-stream"},
                        chunks=native_stream(**fields),
                    )
                ),
            ):
                response = self.haiku_post(stream=True)
                data = response.data
                assert b'"usage_complete":false' in data
                assert b'"completion_tokens":0' not in data

    def test_missing_usage_retains_the_reservation_for_json_and_streams(self):
        self.seed_haiku()
        for usage in (
            None,
            {},
            {"input_tokens": 4},
            {"input_tokens": 4, "output_tokens": True},
        ):
            with (
                self.subTest(usage=usage),
                self.requests(return_value=upstream(message(usage=usage))),
            ):
                response = self.haiku_post()
                assert response.status_code == 200
                assert response.json["usage"] is None
                assert response.json["multillm"]["usage_complete"] is False
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"},
                chunks=native_stream(usage=False),
            )
        ):
            response = self.haiku_post(stream=True)
            data = response.data
        assert b'"usage_complete":false' in data
        assert b'"total_tokens":0' not in data

    def test_tool_replay_and_output_use_the_same_protocol_bridge(self):
        self.seed_haiku()
        schema = {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        }
        tools = [
            {"type": "function", "function": {"name": "weather", "parameters": schema}}
        ]
        calls = [
            {
                "id": "call_previous",
                "type": "function",
                "function": {"name": "weather", "arguments": '{"city":"Kochi"}'},
                "extra_content": {
                    "google": {"thought_signature": "private-signature-canary"}
                },
            }
        ]
        messages = [
            {"role": "user", "content": "weather"},
            {"role": "assistant", "tool_calls": calls},
            {"role": "tool", "tool_call_id": "call_previous", "content": "sunny"},
        ]
        original = deepcopy(messages)
        native = message(
            content=[
                {
                    "type": "tool_use",
                    "id": "toolu_next",
                    "name": "weather",
                    "input": {"city": "Delhi"},
                }
            ],
            stop_reason="tool_use",
        )
        with self.requests(return_value=upstream(native)) as send:
            response = self.haiku_post(
                messages=messages, tools=tools, tool_choice="required"
            )
        assert response.status_code == 200
        assert messages == original
        body = json.loads(send.call_args.kwargs["data"])
        assert body["tools"][0]["input_schema"] == schema
        assert body["messages"][1]["content"][0]["type"] == "tool_use"
        assert body["messages"][2]["content"][0]["type"] == "tool_result"
        assert "private-signature-canary" not in json.dumps(body)
        call = response.json["choices"][0]["message"]["tool_calls"][0]
        assert call["id"] == "toolu_next"
        assert json.loads(call["function"]["arguments"]) == {"city": "Delhi"}

    def test_invalid_json_can_escalate_to_the_reviewed_stronger_fallback(self):
        self.seed_haiku()
        with self.requests(
            side_effect=[
                upstream(message("not JSON")),
                upstream(completion('{"ok":true}')),
            ]
        ) as send:
            response = self.haiku_post(response_format={"type": "json_object"})
        assert response.status_code == 200
        assert response.json["model"] == "openai:fallback"
        assert response.json["multillm"]["escalations"] == 1
        assert response.json["usage"]["total_tokens"] == 12
        assert send.call_count == 2
