import json
from collections import OrderedDict
from types import SimpleNamespace
from unittest.mock import Mock

from flask import Flask, g, request
import pytest
from error_handlers import init_error_handlers, APIError
from services import secret_firewall as firewall
from services.secret_scan import scan_text

TOKEN = "AK" + "IA" + "AB12CD34EF56GH78"

@pytest.fixture(autouse=True)
def reset_audit_window(monkeypatch):
    monkeypatch.setattr(firewall, "_audit_events", OrderedDict())


def application(monkeypatch, mode):
    from services.proxy_service import ProxyService
    from services import audit_log
    events, bodies = [], []
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", mode)
    monkeypatch.setattr(audit_log, "record", lambda *args, **kw: events.append([args, kw]))
    response = SimpleNamespace(status_code=200, headers={"content-type": "application/json"}, close=lambda: None)
    session = Mock()
    session.request.side_effect = lambda **kw: bodies.append(kw["data"]) or response
    monkeypatch.setattr(ProxyService, "_get_provider_session", lambda *args, **kwargs: session)
    monkeypatch.setattr(ProxyService, "_circuit_open_response", lambda *args: None)
    app = Flask(__name__)
    init_error_handlers(app); firewall.init_secret_firewall(app)
    @app.post("/v1/chat/completions")
    def chat():
        g.authenticated_user = {"username": "synthetic-agent", "secret_scan_mode": request.headers.get("scan-mode")}
        headers = {"Content-Type": "application/json", "Content-Length": str(len(request.data))}
        ProxyService._make_base_request("POST", "https://provider.invalid/v1/chat/completions", headers, {}, request.data,
                                       "gguu", use_cache=False, force_raw_passthrough=True)
        # Retry dispatch with identical input uses the request's checked-byte cache.
        ProxyService._make_base_request("POST", "https://provider.invalid/v1/chat/completions", headers, {}, request.data,
                                       "gguu", use_cache=False, force_raw_passthrough=True)
        assert headers["Content-Length"] == str(len(bodies[-1]))
        return {"ok": True}
    return app, events, bodies

@pytest.mark.parametrize("mode", ["off", "observe", "redact", "block"])
def test_provider_bytes_mode_audit_and_headers(monkeypatch, caplog, mode):
    app, events, bodies = application(monkeypatch, mode)
    response = app.test_client().post("/v1/chat/completions", json={"messages": [{"content": TOKEN}]})
    if mode == "block":
        assert response.status_code == 422 and not bodies
        assert response.json["error"] == "secret_detected"
        assert response.json["types"] == {"aws_access_key": 1}
    else:
        assert response.status_code == 200 and len(bodies) == 2
        assert bodies[0] == bodies[1]
        assert (TOKEN.encode() in bodies[0]) == (mode != "redact")
    assert len(events) == (0 if mode == "off" else 1)
    header = response.headers.get(firewall.HEADER)
    assert header == ({"redact": "redacted=1; observed=0", "observe": "redacted=0; observed=1"}.get(mode))
    assert TOKEN not in json.dumps(events) + str(response.headers) + response.get_data(as_text=True) + caplog.text


def test_per_key_override_and_knowledge(monkeypatch):
    app, events, bodies = application(monkeypatch, "block")
    response = app.test_client().post("/v1/chat/completions", headers={"scan-mode": "off"}, json={"prompt": TOKEN})
    assert response.status_code == 200 and TOKEN.encode() in bodies[0] and not events
    for mode in ("redact", "observe", "block"):
        with app.test_request_context("/v1/knowledge/context"):
            with pytest.raises(APIError) as failure:
                firewall.protect_payload({"query": TOKEN}, user={"secret_scan_mode": mode}, knowledge=True)
            assert failure.value.status_code == 422
    assert firewall.protect_payload({"query": TOKEN}, user={"secret_scan_mode": "off"}, knowledge=True)["query"] == TOKEN


def test_multipart_files_preserved_and_fail_open(monkeypatch, caplog):
    from services import audit_log
    monkeypatch.setattr(audit_log, "record", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(TOKEN)))
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "redact")
    body = ("--synthetic\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n" + TOKEN
            + "\r\n--synthetic\r\nContent-Disposition: form-data; name=\"image\"; filename=\"synthetic.bin\"\r\n\r\n").encode() + bytes([0, 255, 254]) + b"\r\n--synthetic--\r\n"
    result = firewall.protect_body(body, {"Content-Type": "multipart/form-data; boundary=synthetic"})
    assert TOKEN.encode() not in result and bytes([0, 255, 254]) in result
    assert TOKEN not in caplog.text
    monkeypatch.setattr(firewall, "redact_payload", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(TOKEN)))
    assert firewall.protect_body(TOKEN.encode(), {"Content-Type": "application/json"}) == TOKEN.encode()
    assert TOKEN not in caplog.text


def test_key_controls_accept_only_modes():
    from services.key_controls import validate
    for mode in ("off", "observe", "redact", "block", None): assert validate({"secret_scan_mode": mode})["secret_scan_mode"] == mode
    for value in ("other", False, 0, [], {}):
        with pytest.raises(APIError): validate({"secret_scan_mode": value})


def test_urlencoded_fields(monkeypatch):
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "redact")
    body = ("prompt=" + "".join("%" + format(ord(char), "02x") for char in TOKEN)).encode()
    from urllib.parse import parse_qs
    result = firewall.protect_body(body, {"Content-Type": "application/x-www-form-urlencoded"})
    assert parse_qs(result.decode())["prompt"][0].startswith("[REDACTED:aws_access_key:")


def test_knowledge_client_checks_before_background_dispatch(monkeypatch):
    from services import knowledge_client
    monkeypatch.setenv("KNOWLEDGE_SERVICE_ENABLED", "true")
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "observe")
    submit = Mock()
    monkeypatch.setattr(knowledge_client, "_submit", submit)
    with pytest.raises(APIError) as failure:
        knowledge_client.dispatch("context", {"username": "synthetic-reader", "scopes": ["knowledge:read"]}, {"query": TOKEN})
    assert failure.value.status_code == 422
    assert failure.value.payload["types"] == {"aws_access_key": 1}
    submit.assert_not_called()


@pytest.mark.parametrize("mode", ["off", "observe", "redact", "block"])
def test_parallel_image_tasks_keep_key_mode_and_counts(monkeypatch, mode):
    from routes.media_images import run_image_tasks
    from services.proxy_service import ProxyService
    app, events, bodies = application(monkeypatch, "redact")
    @app.post("/synthetic-images")
    def images():
        g.authenticated_user = {"username": "synthetic-agent", "secret_scan_mode": mode}
        def send():
            ProxyService._make_base_request("POST", "https://provider.invalid/images", {"Content-Type": "application/json"}, {},
                                           json.dumps({"prompt": TOKEN}).encode(), "gguu", use_cache=False, force_raw_passthrough=True)
            return app.json.response({"data": []})
        return app.json.response({"items": run_image_tasks([send, send])})
    response = app.test_client().post("/synthetic-images", json={})
    assert len(bodies) == (0 if mode == "block" else 2)
    assert len(events) == (0 if mode == "off" else 1)
    assert all(event[1]["actor"] == "synthetic-agent" for event in events)
    if bodies: assert all((TOKEN.encode() in body) == (mode != "redact") for body in bodies)
    assert all(item["status"] == (422 if mode == "block" else 200) for item in response.json["items"])
    assert response.headers.get(firewall.HEADER) == {"redact": "redacted=2; observed=0", "observe": "redacted=0; observed=2"}.get(mode)


def test_image_secret_block_is_not_a_fallback_candidate(monkeypatch):
    from routes import media_images
    monkeypatch.setenv("SECRET_SCAN_DEFAULT", "block")
    monkeypatch.setattr(media_images, "dispatch_auto_route", lambda payload, **kw: kw["dispatch_candidate"](payload, "gguu:synthetic", "selected"))
    with pytest.raises(APIError) as failure:
        media_images._dispatch_single({"prompt": TOKEN}, lambda _: None,
            lambda value: firewall.protect_payload(value), prepare=lambda _p, _m, value: dict(value))
    assert failure.value.status_code == 422 and failure.value.payload["error"] == "secret_detected"


def test_parallel_image_tasks_add_to_counts_recorded_before_fan_out(monkeypatch):
    from routes.media_images import run_image_tasks
    from services.proxy_service import ProxyService
    app, _, bodies = application(monkeypatch, "redact")
    @app.post("/synthetic-images")
    def images():
        g.authenticated_user = {"username": "synthetic-agent", "secret_scan_mode": "redact"}
        g.secret_scan_counts = [1, 0]
        def send():
            ProxyService._make_base_request("POST", "https://provider.invalid/images", {"Content-Type": "application/json"}, {},
                                           json.dumps({"prompt": TOKEN}).encode(), "gguu", use_cache=False, force_raw_passthrough=True)
            return app.json.response({"data": []})
        return app.json.response({"items": run_image_tasks([send, send])})
    response = app.test_client().post("/synthetic-images", json={})
    assert len(bodies) == 2
    # Worker threads must not share the caller's counter list, or counts multiply.
    assert response.headers.get(firewall.HEADER) == "redacted=3; observed=0"


def test_audit_window_expiry_keeps_per_request_headers(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(firewall.time, "monotonic", lambda: now[0])
    app, events, bodies = application(monkeypatch, "redact")
    client = app.test_client()
    for instant, expected in ((0, 1), (599.999, 1), (600, 2), (601, 2)):
        now[0] = instant
        response = client.post("/v1/chat/completions", json={"prompt": TOKEN})
        assert response.headers[firewall.HEADER] == "redacted=1; observed=0"
        assert len(events) == expected
    assert len(bodies) == 8


def test_audit_identity_dimensions_and_oldest_eviction(monkeypatch):
    monkeypatch.setattr(firewall.time, "monotonic", lambda: 0.0)
    types = {"aws_access_key": 1, "github_token": 1}
    base = ("agent", "/chat", "redact", "redacted", types)
    assert firewall._reserve_audit(*base)
    assert not firewall._reserve_audit(*base[:-1], dict(reversed(list(types.items()))))
    variants = [
        ("other", *base[1:]),
        (base[0], "/images", *base[2:]),
        (*base[:2], "observe", *base[3:]),
        (*base[:3], "observed", types),
        (*base[:4], {"aws_access_key": 1}),
    ]
    for args in variants:
        assert firewall._reserve_audit(*args)
    for index in range(1018):
        assert firewall._reserve_audit(f"agent-{index}", *base[1:])
    assert len(firewall._audit_events) == 1024
    assert not firewall._reserve_audit(*base)  # Duplicate reads do not reorder oldest.
    assert firewall._reserve_audit("one-more", *base[1:])
    assert len(firewall._audit_events) == 1024
    assert firewall._reserve_audit(*base)


def test_failed_audit_is_suppressed_without_changing_policy(monkeypatch, caplog):
    from services import audit_log
    now = [0.0]
    monkeypatch.setattr(firewall.time, "monotonic", lambda: now[0])
    record = Mock(side_effect=RuntimeError(TOKEN))
    monkeypatch.setattr(audit_log, "record", record)
    for instant in (0, 1, 600):
        now[0] = instant
        with pytest.raises(APIError):
            firewall.protect_payload(TOKEN, user={"secret_scan_mode": "block"})
    assert record.call_count == 2
    assert TOKEN not in caplog.text
