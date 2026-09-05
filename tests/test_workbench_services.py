import importlib
import json
import sys
from unittest.mock import Mock

import pytest

from error_handlers import APIError
from services.comparison_lab import comparison_payload
from services.connection_profiles import WorkbenchStore, profile_connection, validate_profile
from services.control_plane_backup import capture
from services.workbench_gateway import call_worker, worker_json, worker_origin


@pytest.fixture
def profile():
    return dict(name="Flash - high", kind="roleplay", provider="nanogpt", model="z-ai/glm-5.3-flash",
                mode="pinned", effort="max", billing="subscription-only", fallback="none", memory="auto", recovery="off")


@pytest.fixture
def stores(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    for name in ("AUTH_DB_PATH", "MODEL_REGISTRY_DB_PATH", "RATE_LIMIT_DB_PATH", "CONNECTION_PROFILES_DB_PATH"):
        monkeypatch.setenv(name, str(tmp_path / (name + ".sqlite3")))


def test_profiles_are_owner_scoped_additive_and_backed_up(stores, profile):
    first = WorkbenchStore.save_profile("owner", profile)
    second = WorkbenchStore.save_profile("owner", profile)
    assert first != second
    assert len(WorkbenchStore.profiles("owner")) == 2
    assert WorkbenchStore.profiles("different") == []
    assert len(capture()["tables"]["connection_profiles"]) == 2


@pytest.mark.parametrize("extra", [{"api_key": "synthetic"}, {"endpoint": "https://untrusted.test"}, {"effort": []}, {"mode": "invented"}, {"recovery": "yes"}])
def test_profiles_reject_secrets_urls_and_invalid_values(profile, extra):
    with pytest.raises(APIError):
        validate_profile({**profile, **extra})


def test_profile_exports_correct_endpoints_without_keys(profile):
    exported = profile_connection(profile, "https://worker.test")
    assert exported["endpoint"] == "https://worker.test/roleplay/v1/chat/completions"
    assert exported["body"]["routing"]["billing"] == "subscription-only"
    direct = validate_profile({**profile, "kind": "direct", "memory": "off"})
    assert profile_connection(direct, "https://worker.test", "xhigh")["endpoint"].endswith("/nanogpt/subscription/v1/chat/completions")
    router = validate_profile({**direct, "provider": "openrouter", "billing": "configured"})
    exported = profile_connection(router, "https://worker.test", "xhigh")
    assert exported["endpoint"].endswith("/openrouter/chat/completions")
    assert exported["body"]["reasoning"] == {"effort": "xhigh"}
    assert "Authorization" not in json.dumps(exported)
    with pytest.raises(APIError):
        validate_profile({**direct, "provider": "openrouter"})


def measurement():
    return dict(provider="nanogpt", model="z-ai/glm-5.3-flash", case="continuity", effort="high", status="completed",
                rating=4, ttft_ms=100.5, duration_ms=1000, output_tokens=100, tps=111.0)


def test_reports_accept_measurements_not_content(stores):
    identifier = WorkbenchStore.save_report("owner", [measurement(), measurement()])
    assert WorkbenchStore.reports("owner")[0]["id"] == identifier
    assert WorkbenchStore.reports("other") == []
    for extra in ({"answer": "private text"}, {"tps": float("nan")}, {"rating": True}, {"provider": []}):
        with pytest.raises(APIError):
            WorkbenchStore.save_report("owner", [{**measurement(), **extra}, measurement()])


def test_lab_requires_confirmation_and_uses_fixed_bounded_synthetic_prompts():
    options = dict(case="continuity", provider="nanogpt", model="z-ai/glm-5.3-flash", effort="max", billing="subscription-only")
    with pytest.raises(APIError):
        comparison_payload(options)
    a = comparison_payload({**options, "confirm_billable": True})
    b = comparison_payload({**options, "confirm_billable": True})
    assert a["session_id"] != b["session_id"]
    assert a["messages"] == b["messages"]
    assert a["routing"]["fallback"] == "none" and a["max_tokens"] == 2048
    for extra in ({"prompt": "private"}, {"provider": []}, {"case": {}}, {"model": "bad\x00model"}):
        with pytest.raises(APIError):
            comparison_payload({**options, "confirm_billable": True, **extra})


@pytest.mark.parametrize("origin", ["http://worker.test", "https://user:pass@worker.test", "https://worker.test/path", "https://worker.test?key=synthetic", "https://[invalid", ""])
def test_gateway_rejects_non_origin_configuration(monkeypatch, origin):
    monkeypatch.setenv("WORKBENCH_WORKER_URL", origin)
    with pytest.raises(APIError):
        worker_origin()


def test_gateway_does_not_follow_redirects_or_leak_credentials(monkeypatch):
    monkeypatch.setenv("WORKBENCH_WORKER_URL", "https://worker.test")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-admin")
    session = Mock()
    response = Mock(ok=False, is_redirect=True, status_code=302)
    session.request.return_value = response
    monkeypatch.setattr("services.workbench_gateway.requests.Session", lambda: session)
    with pytest.raises(APIError) as error:
        worker_json("/v1/roleplay/models")
    assert "synthetic-admin" not in str(error.value)
    assert session.request.call_args.kwargs["allow_redirects"] is False
    assert session.trust_env is False
    session.close.assert_called_once()
    with pytest.raises(ValueError):
        call_worker("https://untrusted.test")


@pytest.fixture
def client(stores, monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "workbench-admin")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-workbench-key")
    monkeypatch.setenv("FLASK_SECRET_KEY", "synthetic-flask-secret")
    monkeypatch.setenv("JWT_SECRET", "synthetic-jwt-secret")
    for name in ("app", "route_helpers", "services.auth_service", "routes.core", "routes.workbench"):
        sys.modules.pop(name, None)
    app_module = importlib.import_module("app")
    app = app_module.create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app.test_client() as browser:
        logged_in = browser.post("/login", data={"username": "workbench-admin", "api_key": "synthetic-workbench-key"})
        assert logged_in.status_code == 302
        yield app, browser


def test_workbench_admin_routes_use_csrf_and_never_expose_keys(client, profile, monkeypatch):
    app, browser = client
    page = browser.get("/workbench")
    assert page.status_code == 200
    assert b"synthetic-workbench-key" not in page.data
    assert page.headers["Cache-Control"] == "no-store"
    app.config["WTF_CSRF_ENABLED"] = True
    assert browser.post("/admin/workbench/profiles", json=profile).status_code == 400
    app.config["WTF_CSRF_ENABLED"] = False
    assert browser.post("/admin/workbench/profiles", json=profile).status_code == 201
    assert len(browser.get("/admin/workbench/profiles").json["profiles"]) == 1
    call = Mock()
    monkeypatch.setattr("routes.workbench.call_worker", call)
    assert browser.post("/admin/workbench/lab/run", json={}).status_code == 400
    assert browser.post("/admin/workbench/recovery", json={"action": "regenerate"}).status_code == 400
    call.assert_not_called()
    with browser.session_transaction() as session:
        session.clear()
    assert browser.get("/admin/workbench/profiles").status_code == 302


def test_workbench_revalidates_admin_role(client, monkeypatch):
    _, browser = client
    from services.sqlite_store import connect, storage_path
    with connect(storage_path("AUTH_DB_PATH", "auth.sqlite3")) as connection:
        connection.execute("UPDATE users SET is_admin = 0 WHERE username = ?", ("workbench-admin",))
    response = browser.get("/admin/workbench/profiles")
    assert response.status_code == 403
