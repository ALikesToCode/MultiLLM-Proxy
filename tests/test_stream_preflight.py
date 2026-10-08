"""Bounded precommit validation for managed automatic Chat streams."""

import io
import json
import os
from unittest.mock import Mock, patch

import pytest
import requests
from flask import Flask, Response

from services.stream_preflight import preflight_chat_stream
from tests.unified_api_test_case import UnifiedApiTestCase


def event(delta=None, **fields):
    choice = {"delta": delta or {}, **fields}
    return ("data: " + json.dumps({"choices": [choice]}, ensure_ascii=False) + "\n\n").encode()


DONE = b"data: [DONE]\n\n"


class Chunks:
    def __init__(self, chunks, error=None):
        self.chunks = iter(chunks)
        self.error = error
        self.reads = 0
        self.closes = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.reads += 1
        try:
            return next(self.chunks)
        except StopIteration:
            if self.error:
                raise self.error
            raise

    def close(self):
        self.closes += 1


def stream(chunks, error=None):
    source = Chunks(chunks, error)
    response = Response(source, content_type="text/event-stream")
    callback = Mock()
    response.call_on_close(callback)
    return response, source, callback


@pytest.mark.parametrize("delta", [
    {"content": "hello"},
    {"reasoning_content": "consider"},
    {"reasoning": "consider"},
    {"tool_calls": [{"index": 0, "function": {"arguments": '{"x":'}}]},
    {"function_call": {"arguments": "{"}},
])
def test_useful_delta_validates_without_consuming_the_tail(delta):
    chunks = [b": ping\n\n", event({"role": "assistant"}), event(delta), DONE]
    response, source, callback = stream(chunks)
    result = preflight_chat_stream(response)
    assert result.validated
    assert result.outcome == "validated"
    assert result.response.headers["X-MultiLLM-Stream-Preflight"] == "validated"
    assert source.reads == 3
    assert list(result.response.iter_encoded()) == chunks
    result.response.close()
    result.response.close()
    assert source.closes == callback.call_count == 1


@pytest.mark.parametrize("width", [1, 2, 7, 64])
def test_split_utf8_json_and_sse_replays_exactly_once(width):
    body = b": ping\r\n\r\n" + event({"content": "hé🙂"}).replace(b"\n", b"\r\n") + DONE
    chunks = [body[i:i + width] for i in range(0, len(body), width)]
    response, source, callback = stream(chunks)
    result = preflight_chat_stream(response)
    assert result.validated
    assert b"".join(result.response.iter_encoded()) == body
    result.response.close()
    assert source.closes == callback.call_count == 1


def test_multiline_data_and_bare_cr_are_valid_sse():
    body = b'event: message\rdata: {"choices":\rdata: [{"delta":{"content":"hi"}}]}\r\r'
    response, _, _ = stream([body])
    result = preflight_chat_stream(response)
    assert result.validated
    assert result.response.get_data() == body
    result.response.close()


@pytest.mark.parametrize("chunks", [
    [],
    [DONE],
    [event({"role": "assistant"}), DONE],
    [b'data: {"choices":[]}\n\n', DONE],
    [event({"content": ""}, finish_reason="stop")],
    [event({"tool_calls": [{"function": {"name": "lookup"}}]}), DONE],
    [b'data: {"choices":[{"delta":{"content":"hi"}}]}'],
    [b"data: nope\n\n"],
    [b"not SSE\n\n"],
    [b"data: []\n\n"],
    [b'data: {"choices":"wrong"}\n\n'],
    [b'data: {"choices":[{}]}\n\n'],
    [event({"content": 123})],
    [event({"tool_calls": "wrong"})],
    [b'data: {"choices":[{"delta":{"content":"\\ud800"}}]}\n\n'],
    [b'data: {"choices":[{"delta":{"content":"\xff"}}]}\n\n'],
])
def test_invalid_prefix_returns_real_failure_and_closes_once(chunks):
    response, source, callback = stream(chunks)
    result = preflight_chat_stream(response)
    assert not result.validated
    assert result.outcome == "upstream_stream_invalid"
    assert result.response.status_code == 502
    assert result.response.json["error"]["code"] == "upstream_stream_invalid"
    assert result.response.mimetype == "application/json"
    result.response.close()
    result.response.close()
    assert source.closes == callback.call_count == 1


def test_provider_error_context_is_sanitized_and_not_a_success():
    body = {"error": {
        "message": "Rejected Bearer synthetic-token\napi_key=synthetic-value",
        "type": "provider_error", "code": "capacity",
        "request": {"messages": [{"content": "private"}]},
    }}
    response, source, callback = stream([("data: " + json.dumps(body) + "\n\n").encode()])
    result = preflight_chat_stream(response)
    assert result.response.status_code == 502
    context = result.response.json["error"]["provider_error"]
    assert context["type"] == "provider_error"
    assert context["code"] == "capacity"
    assert "synthetic-token" not in context["message"]
    assert "synthetic-value" not in context["message"]
    assert "request" not in context
    assert source.closes == callback.call_count == 1


def test_event_error_without_json_error_field_fails():
    response, _, _ = stream([b'event: error\ndata: {"message":"Unavailable"}\n\n'])
    result = preflight_chat_stream(response)
    assert result.response.status_code == 502
    assert result.response.json["error"]["provider_error"]["message"] == "Unavailable"


@pytest.mark.parametrize("error", [
    requests.exceptions.ReadTimeout("private detail"),
    TimeoutError("private detail"),
    requests.exceptions.ConnectionError(
        __import__("urllib3").exceptions.ReadTimeoutError(None, None, "private detail")
    ),
])
def test_read_timeout_is_terminal_504(error):
    response, source, callback = stream([b": ping\n\n"], error)
    result = preflight_chat_stream(response)
    assert result.response.status_code == 504
    assert result.outcome == "upstream_stream_timeout"
    assert result.response.json["error"]["code"] == "upstream_stream_timeout"
    assert "private detail" not in result.response.get_data(as_text=True)
    assert source.closes == callback.call_count == 1


def test_iterator_failure_is_sanitized_and_closed():
    response, source, callback = stream([], RuntimeError("private failure"))
    result = preflight_chat_stream(response)
    assert result.response.status_code == 502
    assert "private failure" not in result.response.get_data(as_text=True)
    assert source.closes == callback.call_count == 1


def test_byte_bound_stops_before_reading_another_chunk():
    response, source, callback = stream([b"x" * 16, event({"content": "too late"})])
    result = preflight_chat_stream(response, max_bytes=16)
    assert result.response.status_code == 502
    assert source.reads == 1
    assert source.closes == callback.call_count == 1


def test_byte_bound_rejects_a_useful_event_beyond_the_bound_in_one_chunk():
    response, source, _ = stream([b": " + b"x" * 32 + b"\n\n" + event({"content": "late"})])
    result = preflight_chat_stream(response, max_bytes=16)
    assert result.response.status_code == 502
    assert source.reads == 1


def test_useful_event_inside_an_oversized_first_chunk_is_valid():
    useful = event({"content": "ok"})
    chunks = [useful + b"x" * 100000]
    response, source, _ = stream(chunks)
    result = preflight_chat_stream(response, max_bytes=len(useful) + 10)
    assert result.validated
    assert list(result.response.iter_encoded()) == chunks
    result.response.close()
    assert source.closes == 1


def test_useful_event_at_byte_bound_replays_the_uninspected_tail():
    useful = event({"content": "ok"})
    chunks = [useful, b"x" * 100000]
    response, source, _ = stream(chunks)
    result = preflight_chat_stream(response, max_bytes=len(useful))
    assert result.validated
    assert list(result.response.iter_encoded()) == chunks
    result.response.close()
    assert source.closes == 1


def test_event_bound_counts_heartbeats_and_empty_deltas():
    response, source, _ = stream([
        b": ping\n\n", event({"role": "assistant"}), event({"content": "too late"})
    ])
    result = preflight_chat_stream(response, max_events=2)
    assert result.response.status_code == 502
    assert source.reads == 2


def test_useful_event_at_event_bound_is_valid():
    response, _, _ = stream([b": ping\n\n" + event({"content": "ok"})])
    result = preflight_chat_stream(response, max_events=2)
    assert result.validated
    result.response.close()


@pytest.mark.parametrize("consume", [False, True])
def test_downstream_abort_closes_original_iterator_and_callbacks_once(consume):
    response, source, callback = stream([event({"content": "ok"}), DONE])
    result = preflight_chat_stream(response)
    iterator = result.response.iter_encoded()
    if consume:
        next(iterator)
    iterator.close()
    result.response.close()
    result.response.close()
    assert source.reads == 1
    assert source.closes == callback.call_count == 1


def test_errors_after_validation_are_replayed_unchanged():
    chunks = [event({"content": "ok"}), b"data: malformed\n\n"]
    response, source, _ = stream(chunks)
    result = preflight_chat_stream(response)
    assert result.validated
    assert list(result.response.iter_encoded()) == chunks
    result.response.close()
    assert source.closes == 1


def test_transformed_bridge_iterator_is_validated_and_replayed():
    from routes.protocol_bridge import translate_downstream_response
    native = [
        b'event: message_start\ndata: {"type":"message_start","message":{"id":"m","model":"m","usage":{}}}\n\n',
        b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Salut"}}\n\n',
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n',
    ]
    from route_helpers import stream_upstream_response
    upstream = requests.Response()
    upstream.status_code = 200
    upstream.headers["Content-Type"] = "text/event-stream"
    upstream.raw = io.BytesIO(b"".join(native))
    upstream.close = Mock(wraps=upstream.close)
    original = stream_upstream_response(upstream)
    bridge = translate_downstream_response(original, source="messages", target="chat", stream=True)
    result = preflight_chat_stream(bridge)
    assert result.validated
    body = result.response.get_data()
    assert b"Salut" in body
    assert b"message_start" not in body
    result.response.close()
    upstream.close.assert_called_once()


def test_non_success_response_is_untouched():
    response = Response(b'{"error":"unavailable"}', status=503)
    result = preflight_chat_stream(response)
    assert result.response is response
    assert result.outcome == "skipped"


class ManagedStreamRouteTest(UnifiedApiTestCase):
    def setUp(self):
        super().setUp()
        os.environ["MULTILLM_STREAM_PREFLIGHT"] = "strict"
        from services.auto_route_service import AutoRouteService
        AutoRouteService.save_route(
            "auto:preflight-test", ["opencode:kimi-k2.6", "opencode:glm-5.2"],
            self.app.config["API_BASE_URLS"],
        )

    def post_stream(self, chunks, *, model="auto:preflight-test", path="/v1/chat/completions"):
        upstream = requests.Response()
        upstream.status_code = 200
        upstream.headers["Content-Type"] = "text/event-stream"
        upstream.raw = io.BytesIO(b"".join(chunks))
        with patch("app.ProxyService.make_request", return_value=upstream) as dispatch:
            response = self.client.post(
                path, headers={"Authorization": "Bearer admin-test-key"},
                json={"model": model, "stream": True, **(
                    {"input": "hi"} if path == "/v1/responses" else
                    {"messages": [{"role": "user", "content": "hi"}]}
                )},
            )
            response.get_data()
        response.close()
        return response, dispatch

    def test_invalid_200_does_not_send_second_post_or_record_health_success(self):
        with patch("routes.auto_routes.RouteHealth.record") as health:
            response, dispatch = self.post_stream([event({"role": "assistant"}), DONE])
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json["error"]["code"], "upstream_stream_invalid")
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(response.headers["X-MultiLLM-Auto-Attempts"], "1")
        self.assertEqual(health.call_count, 1)
        self.assertFalse(health.call_args.kwargs["ok"])
        self.assertEqual(health.call_args.kwargs["outcome"], "upstream_stream_invalid")

    def test_valid_stream_records_health_after_validation(self):
        with patch("routes.auto_routes.RouteHealth.record") as health:
            response, dispatch = self.post_stream([event({"content": "hello"}), DONE])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-MultiLLM-Stream-Preflight"], "validated")
        self.assertEqual(dispatch.call_count, 1)
        self.assertTrue(health.call_args.kwargs["ok"])

    def test_off_mode_preserves_headers_and_bytes(self):
        os.environ["MULTILLM_STREAM_PREFLIGHT"] = "off"
        chunks = [event({"role": "assistant"}), DONE]
        response, dispatch = self.post_stream(chunks)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"".join(chunks))
        self.assertNotIn("X-MultiLLM-Stream-Preflight", response.headers)
        self.assertEqual(dispatch.call_count, 1)

    def test_explicit_provider_stream_is_untouched(self):
        chunks = [event({"role": "assistant"}), DONE]
        response, dispatch = self.post_stream(chunks, model="opencode:kimi-k2.6")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"".join(chunks))
        self.assertNotIn("X-MultiLLM-Stream-Preflight", response.headers)
        self.assertEqual(dispatch.call_count, 1)

    def test_nonstream_request_is_untouched(self):
        with patch("app.ProxyService.make_request", return_value=self._chat_response()):
            response = self.client.post(
                "/v1/chat/completions", headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "auto:preflight-test", "messages": [{"role": "user", "content": "hi"}]},
            )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("X-MultiLLM-Stream-Preflight", response.headers)

    def test_other_protocol_auto_stream_is_untouched(self):
        with patch("routes.auto_routes.preflight_chat_stream") as gate:
            response, dispatch = self.post_stream([event({"content": "hello"}), DONE], path="/v1/responses")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(dispatch.call_count, 1)
        gate.assert_not_called()


    def test_raw_provider_route_is_untouched(self):
        chunks = [event({"role": "assistant"}), DONE]
        with patch("routes.auto_routes.preflight_chat_stream") as gate:
            response, dispatch = self.post_stream(
                chunks, model="kimi-k2.6", path="/opencode/v1/chat/completions",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"".join(chunks))
        self.assertNotIn("X-MultiLLM-Stream-Preflight", response.headers)
        self.assertEqual(dispatch.call_count, 1)
        gate.assert_not_called()

    def test_timeout_is_terminal_and_has_no_second_dispatch(self):
        downstream, source, callback = stream([], requests.exceptions.ReadTimeout("private"))
        with patch(
            "routes.unified._dispatch_unified_chat_candidate", return_value=downstream,
        ) as dispatch, patch("routes.auto_routes.RouteHealth.record") as health:
            response = self.client.post(
                "/v1/chat/completions", headers={"Authorization": "Bearer admin-test-key"},
                json={"model": "auto:preflight-test", "stream": True,
                      "messages": [{"role": "user", "content": "hi"}]},
            )
        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.json["error"]["code"], "upstream_stream_timeout")
        self.assertEqual(dispatch.call_count, 1)
        self.assertFalse(health.call_args.kwargs["ok"])
        self.assertEqual(source.closes, 1)
        callback.assert_called_once()


@pytest.mark.parametrize("mode", ["off", "", "unknown", None])
def test_disabled_dispatch_never_reads_or_wraps_response(mode, monkeypatch):
    from routes.auto_routes import dispatch_auto_route_chat_completion
    from services.auto_route_service import AutoRoute
    if mode is None:
        monkeypatch.delenv("MULTILLM_STREAM_PREFLIGHT", raising=False)
    else:
        monkeypatch.setenv("MULTILLM_STREAM_PREFLIGHT", mode)
    original, source, _ = stream([DONE])
    app = Flask(__name__)
    with app.test_request_context("/v1/chat/completions", method="POST"), patch(
        "routes.auto_routes.AutoRouteService.get_route",
        return_value=AutoRoute("auto:test", ("opencode:test",), "2026-10-09"),
    ), patch("routes.auto_routes.RouteHealth.record"):
        result = dispatch_auto_route_chat_completion(
            {"model": "auto:test", "stream": True},
            validate_candidate=lambda _: None, dispatch_candidate=lambda *_: original,
        )
    assert result is original
    assert source.reads == 0
    assert "X-MultiLLM-Stream-Preflight" not in result.headers
    result.close()

def test_lazy_bridge_failure_retains_sanitized_provider_context():
    from services.protocol_translation import UpstreamFailure
    response, source, callback = stream([], UpstreamFailure(
        "Failed Bearer synthetic-token", error_type="provider_error", code="capacity",
    ))
    result = preflight_chat_stream(response)
    assert result.response.status_code == 502
    assert result.response.json["error"]["provider_error"] == {
        "message": "Failed <redacted>", "type": "provider_error", "code": "capacity",
    }
    assert source.closes == callback.call_count == 1


def test_successful_non_sse_response_is_invalid_and_closed():
    response = Response(b'{"choices":[]}', content_type="application/json")
    callback = Mock()
    response.call_on_close(callback)
    result = preflight_chat_stream(response)
    assert result.response.status_code == 502
    assert result.response.json["error"]["code"] == "upstream_stream_invalid"
    callback.assert_called_once()


@pytest.mark.parametrize("max_bytes,max_events", [(0, 1), (1, 0), (-1, 1)])
def test_invalid_bounds_do_not_consume_response(max_bytes, max_events):
    response, source, _ = stream([DONE])
    with pytest.raises(ValueError):
        preflight_chat_stream(response, max_bytes=max_bytes, max_events=max_events)
    assert source.reads == 0
    response.close()

def test_oversized_chunk_without_useful_prefix_fails_after_one_read():
    response, source, callback = stream([b"x" * 100000])
    result = preflight_chat_stream(response, max_bytes=64)
    assert result.response.status_code == 502
    assert not result.validated
    assert source.reads == 1
    assert source.closes == callback.call_count == 1
