import json
import threading
import time

from services.control_plane_backup import capture
from services.intelligence_store import IntelligenceStore
from tests.intelligence_fixtures import IntelligenceApiTestCase, frames, upstream
from tests.test_intelligence_http import TOOL
from tests.test_intelligence_policy import candidate, policy


def delta(value, finish=None):
    return {"choices": [{"index": 0, "delta": value, "finish_reason": finish}]}


def events(response):
    return [
        json.loads(line[6:])
        for line in response.data.decode().splitlines()
        if line.startswith("data: ") and line != "data: [DONE]"
    ]


class IntelligenceStreamTests(IntelligenceApiTestCase):
    def test_audio_deltas_are_preserved_for_a_reviewed_audio_model(self):
        IntelligenceStore.seed(
            policy(
                candidates=[
                    candidate(
                        "openai:small",
                        capabilities=["audio", "streaming"],
                        media_input_tokens=8192,
                    )
                ]
            )
        )
        stream = frames(
            delta({"audio": {"id": "audio-1", "data": "YQ=="}}),
            delta({}, "stop"),
            "[DONE]",
        )
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"}, chunks=stream
            )
        ):
            response = self.post(
                stream=True,
                modalities=["audio"],
                audio={"voice": "test", "format": "pcm16"},
            )
            output = events(response)
        assert output[0]["choices"][0]["delta"]["audio"]["data"] == "YQ=="
        assert "error" not in output[-1]
        assert output[-1]["multillm"]["usage_complete"] is False

    def test_terminal_event_has_usage_and_metadata_before_done(self):
        self.seed()
        stream = frames(
            delta({"role": "assistant", "reasoning_content": "secret reasoning"}),
            delta({"content": "hello"}),
            delta({}, "stop"),
            {
                "choices": [],
                "usage": {
                    "prompt_tokens": 4,
                    "completion_tokens": 2,
                    "total_tokens": 6,
                },
            },
            "[DONE]",
        )
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"}, chunks=stream
            )
        ):
            response = self.post(stream=True, stream_options={"include_usage": True})
            output = events(response)
        assert response.status_code == 200
        assert output[-1]["multillm"]["usage_complete"]
        assert output[-1]["usage"]["total_tokens"] == 6
        assert response.data.endswith(b"data: [DONE]\n\n")
        assert b"secret reasoning" not in response.data

    def test_indexed_tool_call_deltas_are_preserved_and_validated(self):
        self.seed()
        first = {
            "index": 0,
            "id": "call-1",
            "type": "function",
            "function": {"name": "lookup", "arguments": '{"q":'},
        }
        second = {"index": 0, "function": {"arguments": '"test"}'}}
        stream = frames(
            delta({"tool_calls": [first]}),
            delta({"tool_calls": [second]}),
            delta({}, "tool_calls"),
            {
                "choices": [],
                "usage": {
                    "prompt_tokens": 4,
                    "completion_tokens": 2,
                    "total_tokens": 6,
                },
            },
            "[DONE]",
        )
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"}, chunks=stream
            )
        ):
            response = self.post(stream=True, tools=[TOOL])
            output = events(response)
        assert output[0]["choices"][0]["delta"]["tool_calls"] == [first]
        assert output[1]["choices"][0]["delta"]["tool_calls"] == [second]
        assert output[-1]["multillm"]["attempts"] == 1

    def test_schema_stream_is_gated_and_escalation_usage_is_aggregated(self):
        self.seed()
        usage = {
            "choices": [],
            "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
        }
        with self.requests(
            side_effect=[
                upstream(
                    headers={"Content-Type": "text/event-stream"},
                    chunks=frames(
                        delta({"content": "bad"}), delta({}, "stop"), usage, "[DONE]"
                    ),
                ),
                upstream(
                    headers={"Content-Type": "text/event-stream"},
                    chunks=frames(
                        delta({"content": '{"ok":true}'}),
                        delta({}, "stop"),
                        usage,
                        "[DONE]",
                    ),
                ),
            ]
        ) as send:
            response = self.post(stream=True, response_format={"type": "json_object"})
            output = events(response)
        assert send.call_count == 2
        assert b'"bad"' not in response.data
        assert output[-1]["usage"]["total_tokens"] == 12
        assert output[-1]["multillm"]["escalations"] == 1

    def test_partial_output_never_gets_a_replacement_after_interruption(self):
        self.seed()
        stream = frames(
            delta({"content": "partial"}), {"error": {"message": "provider-secret"}}
        )
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"}, chunks=stream
            )
        ) as send:
            response = self.post(stream=True)
            output = events(response)
        assert send.call_count == 1
        assert output[0]["choices"][0]["delta"]["content"] == "partial"
        assert output[-1]["error"]["code"] == "stream_interrupted"
        assert output[-1]["multillm"]["usage_complete"] is False
        assert b"provider-secret" not in response.data

    def test_truncated_stream_reports_an_interruption_not_a_success(self):
        self.seed()
        with self.requests(
            return_value=upstream(
                headers={"Content-Type": "text/event-stream"},
                chunks=frames(delta({"content": "partial"})),
            )
        ) as send:
            response = self.post(stream=True)
            output = events(response)
        assert (
            send.call_count == 1 and output[-1]["error"]["code"] == "stream_interrupted"
        )

    def test_provisional_usage_cannot_settle_a_completed_stream(self):
        self.seed()
        stream = frames(
            {
                "choices": [],
                "usage": {
                    "prompt_tokens": 4,
                    "completion_tokens": 2,
                    "total_tokens": 6,
                },
            },
            delta({"content": "hello"}),
            delta({}, "stop"),
            "[DONE]",
        )
        with self.requests(return_value=upstream(chunks=stream)):
            response = self.post(stream=True)
            output = events(response)
        assert output[-1]["usage"] is None
        assert not output[-1]["multillm"]["usage_complete"]

    def test_output_after_finish_is_an_interruption_and_is_not_appended(self):
        self.seed()
        stream = frames(
            delta({"content": "first answer"}),
            delta({}, "stop"),
            delta({"content": "replacement answer"}),
            "[DONE]",
        )
        with self.requests(return_value=upstream(chunks=stream)) as send:
            response = self.post(stream=True)
            output = events(response)
        assert output[-1]["error"]["code"] == "stream_interrupted"
        assert b"replacement answer" not in response.data
        assert send.call_count == 1

    def test_caller_cancellation_during_header_wait_never_fails_over(self):
        self.seed()
        entered, release = threading.Event(), threading.Event()

        def send_later(**kwargs):
            entered.set()
            release.wait(2)
            return upstream({}, 429)

        with self.requests(side_effect=send_later) as send:
            response = self.client.post(
                "/v1/chat/completions",
                headers=self.headers,
                json={
                    "model": "auto:intelligence",
                    "messages": [{"role": "user", "content": "test"}],
                    "stream": True,
                },
                buffered=False,
            )
            assert entered.wait(1)
            response.close()
            release.set()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                rows = capture()["tables"]["intelligence_reservations"]
                if rows and rows[0]["state"] != "pending":
                    break
                time.sleep(0.01)
            assert send.call_count == 1
        assert rows[0]["state"] == "unknown"
