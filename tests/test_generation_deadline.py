"""Generation budgets with fake clocks and synthetic upstreams."""
import json
from unittest.mock import Mock, patch

import pytest
import requests
from flask import Flask, Response, g

from services import generation_deadline as gd
from services.proxy_service import ProxyService
from services.resilience_service import ResilienceService


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setenv("GENERATION_DEADLINE_MAX_MS", "")
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "off")
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", "false")
    ResilienceService.reset()
    yield
    ResilienceService.reset()


def upstream(status=200):
    response = requests.Response()
    response.status_code = status
    response._content = b'{}'
    response.headers = {"Content-Type": "application/json", "Retry-After": "20"}
    response.close = Mock()
    return response


def test_absent_is_identity_even_with_spoofed_internal_budget():
    assert gd.deadline_from_headers({gd.INTERNAL_HEADER: "1"}) is None
    app = Flask(__name__)
    gd.register_generation_deadline(app)
    with app.test_request_context("/v1/chat/completions", method="POST"):
        assert gd.current_deadline() is None
        assert gd.bounded_timeout((5, 60)) == (5, 60)


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "300001", "bad", ""])
def test_invalid_header_is_rejected(value):
    with pytest.raises(gd.InvalidGenerationDeadline):
        gd.deadline_from_headers({gd.PUBLIC_HEADER: value})


def test_one_clock_minimum_and_authenticated_transport():
    clock = Clock()
    deadline = gd.deadline_from_headers(
        {gd.PUBLIC_HEADER: "1000", gd.INTERNAL_HEADER: "100"}, clock=clock,
        limits_ms=(500,),
    )
    assert deadline.remaining_ms() == 500
    clock.now += .2
    assert 299 <= deadline.remaining_ms() <= 300
    forwarded = gd.forwarded_headers({gd.INTERNAL_HEADER: "99999"}, deadline)
    assert int(forwarded[gd.INTERNAL_HEADER]) <= 300
    remote = gd.deadline_from_headers(forwarded, trusted_internal=True, clock=lambda: 900)
    assert remote.expires_at < 901
    assert gd.forwarded_headers({gd.INTERNAL_HEADER: "1"}, None) == {}


def test_malformed_maximum_disables_without_logging_value(monkeypatch, caplog):
    monkeypatch.setenv("GENERATION_DEADLINE_MAX_MS", "private-invalid")
    assert gd.deadline_from_headers({gd.PUBLIC_HEADER: "100"}) is None
    assert gd.deadline_from_headers({gd.PUBLIC_HEADER: "100"}) is None
    assert "private-invalid" not in caplog.text


def test_setup_and_token_count_consume_transport_budget():
    clock = Clock()
    app = Flask(__name__)
    session = Mock()
    session.request.return_value = upstream()
    with app.test_request_context():
        g.generation_deadline = gd.Deadline(101, clock)
        clock.now += .75
        with patch.object(ProxyService, "_get_provider_session", return_value=session):
            result = ProxyService._make_base_request("POST", "https://example.invalid", {}, {}, b'{}', "openai")
        assert result.status_code == 200
        assert sum(session.request.call_args.kwargs["timeout"]) <= .25
        clock.now = 102
        with patch.object(ProxyService, "_get_provider_session", return_value=session):
            with pytest.raises(gd.GenerationDeadlineExceeded):
                ProxyService._make_request_with_timeout("POST", "https://example.invalid", {}, {}, b'{}', (5, 60))
        assert session.request.call_count == 1


@pytest.mark.parametrize("advice", ["false", "true"])
def test_retry_wait_cannot_overrun_or_replay(monkeypatch, advice):
    monkeypatch.setenv("UPSTREAM_RETRY_AFTER_ADVICE_ENABLED", advice)
    clock = Clock()
    response = upstream(429)
    session = Mock(request=Mock(return_value=response))
    with Flask(__name__).test_request_context():
        g.generation_deadline = gd.Deadline(100.5, clock)
        with patch.object(ProxyService, "_get_provider_session", return_value=session), patch("services.proxy_service.time.sleep") as sleep:
            with pytest.raises(gd.GenerationDeadlineExceeded):
                ProxyService._make_base_request("GET", "https://example.invalid", {}, {}, None, "openai")
        assert session.request.call_count == 1
        sleep.assert_not_called()
        assert response.multillm_cancellation.outcome.usage_state == "unknown"
        assert not response.multillm_cancellation.outcome.upstream.replay_permission


def test_midstream_error_is_real_and_cancellation_is_ambiguous():
    clock = Clock()
    source = upstream()
    def chunks():
        yield b'data: {"choices":[{"delta":{"content":"a"}}]}\n\n'
        clock.now = 102
        yield b'data: [DONE]\n\n'
    response = Response(chunks(), content_type="text/event-stream")
    body = gd.DeadlineIterator(iter(response.response), gd.Deadline(101, clock), source)
    assert b'"content"' in next(body)
    error = next(body)
    assert b"generation_deadline_exceeded" in error and b"[DONE]" not in error
    assert list(body) == []
    assert source.multillm_cancellation.outcome.ambiguous
    assert source.multillm_cancellation.outcome.usage is None


def test_preflight_expiry_is_504_through_registered_callback():
    clock = Clock()
    app = Flask(__name__)
    gd.register_generation_deadline(app, clock=clock)
    @app.before_request
    def authorized():
        return gd.generation_deadline_hook()
    @app.post("/v1/chat/completions")
    def generate():
        def chunks():
            yield b': heartbeat\n\n'
            clock.now += 2
            yield b'data: {"choices":[{"delta":{"content":"late"}}]}\n\n'
        return Response(chunks(), content_type="text/event-stream")
    result = app.test_client().post("/v1/chat/completions", headers={gd.PUBLIC_HEADER: "1000"})
    assert result.status_code == 504
    assert result.json["error"]["code"] == "generation_deadline_exceeded"


def test_expiry_releases_half_open_probe_without_healing():
    clock = Clock()
    ResilienceService._states["openai"] = {**ResilienceService._new_state(), "state": "half_open"}
    def setup(*args, **kwargs):
        clock.now = 102
        return Mock()
    with Flask(__name__).test_request_context():
        g.generation_deadline = gd.Deadline(101, clock)
        with patch.object(ProxyService, "_get_provider_session", side_effect=setup):
            with pytest.raises(gd.GenerationDeadlineExceeded):
                ProxyService._make_base_request("GET", "https://example.invalid", {}, {}, None, "openai")
    state = ResilienceService.snapshot("openai")
    assert state["half_open_in_flight"] == state["total_successes"] == 0


def test_internal_budget_requires_verification_and_caps_admission():
    app = Flask(__name__)
    gd.register_generation_deadline(app, verify_internal=lambda: True, limits_ms=lambda: (500,))
    with app.test_request_context("/v1/chat/completions", method="POST", headers={gd.INTERNAL_HEADER: "100"}):
        gd.generation_deadline_hook()
        deadline = gd.current_deadline()
        assert deadline.remaining() <= .1
        assert g.cascade_deadline == g.gateway_generation_deadline == deadline.expires_at
        deadline.stop()


def test_unknown_final_usage_keeps_ambiguous_settlement():
    from services.request_cancellation import CancellationContext
    owner = CancellationContext(lambda: None)
    owner.handoff()
    owner.complete()
    result = gd.settlement_information(owner)
    assert result["ambiguous"] and result["usage_state"] == "unknown"
    assert not result["replay_permission"]


def test_auto_route_expiry_stops_next_candidate_and_closes_response():
    from routes import auto_routes
    from services.auto_route_service import AutoRoute
    clock = Clock()
    close = Mock()
    calls = []
    route = AutoRoute("auto:synthetic", "synthetic", ["openai:first", "openai:second"])
    def dispatch(*args):
        calls.append(args)
        clock.now = 102
        response = Response("refusal", status=429)
        response.call_on_close(close)
        return response
    with Flask(__name__).test_request_context():
        g.generation_deadline = gd.Deadline(101, clock)
        with patch.object(auto_routes.AutoRouteService, "get_route", return_value=route):
            with pytest.raises(gd.GenerationDeadlineExceeded):
                auto_routes.dispatch_auto_route({"model": "auto:synthetic"}, validate_candidate=lambda model: None, dispatch_candidate=dispatch)
    assert len(calls) == close.call_count == 1


def test_registered_raw_defaults_preserve_binary_and_headers():
    app = Flask(__name__)
    gd.register_generation_deadline(app)
    @app.before_request
    def authorized():
        return gd.generation_deadline_hook()
    @app.post("/v1/chat/completions")
    def generate():
        return Response(iter([b"\x00\xff", b"raw"]), content_type="application/octet-stream", headers={"X-Test": "same"})
    result = app.test_client().post("/v1/chat/completions", headers={gd.INTERNAL_HEADER: "1"})
    assert result.status_code == 200 and result.data == b"\x00\xffraw"
    assert result.headers["X-Test"] == "same"


def test_active_deadline_does_not_retry_ambiguous_post_timeout():
    session = Mock(request=Mock(side_effect=requests.ReadTimeout("synthetic")))
    with Flask(__name__).test_request_context():
        g.generation_deadline = gd.Deadline(101, Clock())
        with patch.object(ProxyService, "_get_provider_session", return_value=session):
            result = ProxyService._make_base_request("POST", "https://example.invalid", {}, {}, b'{}', "openai")
        assert result.status_code == 502 and session.request.call_count == 1


@pytest.mark.parametrize("path", ["/v1/responses", "/v1/messages"])
def test_other_protocol_precommit_expiry_is_504(path):
    clock = Clock()
    app = Flask(__name__)
    gd.register_generation_deadline(app, clock=clock)
    @app.before_request
    def authorized():
        return gd.generation_deadline_hook()
    def generate():
        def chunks():
            yield b': heartbeat\n\n'
            clock.now += 2
            yield b'data: {"type":"content_block_delta","delta":{"text":"late"}}\n\n'
        return Response(chunks(), content_type="text/event-stream")
    app.add_url_rule(path, view_func=generate, methods=["POST"])
    result = app.test_client().post(path, headers={gd.PUBLIC_HEADER: "1000"})
    assert result.status_code == 504


@pytest.mark.parametrize("protocol", ["responses", "anthropic"])
def test_protocol_error_event_contains_error_type(protocol):
    clock = Clock()
    def chunks():
        yield b'data: useful\n\n'
        clock.now += 2
        yield b'data: [DONE]\n\n'
    body = gd.DeadlineIterator(chunks(), gd.Deadline(101, clock), upstream(), protocol=protocol)
    next(body)
    event = next(body)
    assert b'"type": "error"' in event
    if protocol == "anthropic":
        assert json.loads(event.split(b"data: ", 1)[1])["error"]["type"] == "api_error"
    assert list(body) == []


def test_prefix_bound_does_not_commit_heartbeats_as_success():
    app = Flask(__name__)
    gd.register_generation_deadline(app)
    @app.before_request
    def authorized():
        return gd.generation_deadline_hook()
    @app.post("/v1/responses")
    def generate():
        return Response(iter([b': heartbeat\n\n' * 6000]), content_type="text/event-stream")
    result = app.test_client().post("/v1/responses", headers={gd.PUBLIC_HEADER: "1000"})
    assert result.status_code == 502
    assert result.json["error"]["code"] == "upstream_stream_invalid"
