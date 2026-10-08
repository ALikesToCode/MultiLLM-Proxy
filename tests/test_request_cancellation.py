"""Cancellation ownership with synthetic HTTP responses only."""

from unittest.mock import Mock

import pytest
import requests
from flask import Flask, Response

from routes.unified_transport import send_unified_provider_request
from services.request_cancellation import CancellationContext, bind_cancellation
from services.stream_preflight import preflight_chat_stream
from services.upstream_transport import (
    close_retry_response, iter_stream_content, iter_stream_lines,
)


class Upstream:
    status_code = 200

    def __init__(self, chunks=(), error=None):
        self.headers = {"content-type": "text/event-stream"}
        self.chunks = chunks
        self.error = error
        self.closes = 0
        self.reads = 0

    def iter_content(self, chunk_size):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk
        if self.error:
            raise self.error

    def iter_lines(self, decode_unicode=True):
        raise AssertionError("Socket failures must not restart stream consumption")

    def close(self):
        self.closes += 1


@pytest.mark.parametrize("started", [False, True])
def test_close_before_or_after_first_byte_is_ambiguous_once(started):
    upstream = Upstream([b"first", b"second"])
    observed = Mock()
    context = bind_cancellation(upstream, on_outcome=observed)
    body = iter_stream_content(upstream)
    if started:
        assert next(body) == b"first"
    body.close()
    upstream.close()
    close_retry_response(upstream)
    assert upstream.closes == observed.call_count == 1
    assert context.outcome.ambiguous
    assert context.outcome.usage_state == "unknown"
    assert context.outcome.usage is None
    assert not context.outcome.upstream.replay_permission
    assert context.outcome.upstream.credential_health == "unknown"
    assert upstream.reads == int(started)


def test_generator_exit_closes_once():
    upstream = Upstream([b"first", b"second"])
    body = iter_stream_content(upstream)
    next(body)
    with pytest.raises(GeneratorExit):
        body.throw(GeneratorExit)
    body.close()
    upstream.close()
    assert upstream.closes == 1


def test_socket_timeout_closes_without_line_fallback():
    upstream = Upstream(error=requests.ReadTimeout("synthetic timeout"))
    with pytest.raises(requests.ReadTimeout):
        list(iter_stream_lines(upstream))
    upstream.close()
    assert upstream.closes == 1
    assert upstream.multillm_cancellation.outcome.ambiguous
    assert not upstream.multillm_cancellation.outcome.upstream.replay_permission


def test_completed_raw_bytes_are_unchanged():
    chunks = [b": ping\r\n\r\n", b"data: raw\n\n", b"\x00\xff"]
    upstream = Upstream(chunks)
    assert list(iter_stream_content(upstream)) == chunks
    upstream.close()
    assert upstream.closes == 1
    assert not upstream.multillm_cancellation.outcome.ambiguous
    assert upstream.multillm_cancellation.outcome.reason == "complete"


@pytest.mark.parametrize("chunks", [[], [b"data: [DONE]\n\n"]])
def test_preflight_rejection_closes_upstream_once(chunks):
    upstream = Upstream(chunks)
    response = Response(iter_stream_content(upstream), content_type="text/event-stream")
    response.call_on_close(upstream.close)
    result = preflight_chat_stream(response)
    assert not result.validated
    assert result.response.status_code == 502
    result.response.close()
    upstream.close()
    assert upstream.closes == 1


@pytest.mark.parametrize("started", [False, True])
def test_unified_flask_handoff_closes_owned_body_before_or_after_iteration(started):
    upstream = Upstream([b"first", b"second"])
    body = iter_stream_content(upstream)
    response = Response(body, headers={"X-Request-ID": "synthetic"})
    proxy = Mock()
    proxy.make_request.return_value = response
    result = send_unified_provider_request(
        proxy, {"method": "POST", "data": b"raw"}, provider="openai",
        primary_origin="https://example.invalid", secondary_origin=None,
        upstream_path="v1/chat/completions", request_headers={},
    )
    if started:
        assert next(iter(result.response)) == b"first"
    result.close()
    result.close()
    assert upstream.closes == 1
    assert result.headers["X-Request-ID"] == "synthetic"
    assert result.multillm_cancellation.outcome.ambiguous


def test_registered_wsgi_response_close_owns_unstarted_stream():
    app = Flask(__name__)
    upstream = Upstream([b"one", b"two"])

    @app.route("/synthetic")
    def synthetic():
        proxy = Mock()
        proxy.make_request.return_value = Response(iter_stream_content(upstream))
        return send_unified_provider_request(
            proxy, {"method": "POST"}, provider="openai",
            primary_origin="https://example.invalid", secondary_origin=None,
            upstream_path="v1/chat/completions", request_headers={},
        )

    response = app.test_client().get("/synthetic", buffered=False)
    response.close()
    assert upstream.closes == 1


def test_cleanup_and_observer_failures_do_not_mask_disconnect(caplog):
    upstream = Upstream()
    upstream.close = Mock(side_effect=RuntimeError("private content"))
    original_close = upstream.close
    context = bind_cancellation(upstream, on_outcome=Mock(side_effect=ValueError("private content")))
    context.close()
    context.close()
    assert original_close.call_count == 1
    assert "private content" not in caplog.text


def test_cancellation_before_handoff_has_no_usage_claim_or_replay():
    close = Mock()
    context = CancellationContext(close)
    context.cancel()
    context.cancel()
    assert close.call_count == 1
    assert not context.outcome.ambiguous
    assert context.outcome.usage is None
    assert not context.outcome.upstream.replay_permission
