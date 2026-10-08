"""Immutable prompt versions through registered routes and bounded stores."""

import hashlib
import importlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

import pytest
from flask import Flask
from flask_wtf.csrf import CSRFProtect

from error_handlers import APIError, init_error_handlers
from routes.workbench import register_workbench_routes
from routes.csrf_errors import handle_csrf_error
from flask_wtf.csrf import CSRFError
from services import prompt_templates as templates

TEMPLATE = {"slug": "greeting", "version": 1, "content": "Hello {{name}} / {{name}}", "variables": ["name"]}


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("CONNECTION_PROFILES_DB_PATH", str(tmp_path / "workbench.sqlite3"))
    monkeypatch.delenv("PROMPT_TEMPLATES_ENABLED", raising=False)
    monkeypatch.setattr("requests.Session", Mock(side_effect=AssertionError("Unexpected HTTP call")))


def patch_auth(monkeypatch, name, value):
    """Patch the AuthService the registered routes call; other suites re-import route_helpers and routes.core."""
    prompt_routes = importlib.import_module("routes.prompt_templates")
    functions = (register_workbench_routes.__globals__["login_required"],
                 register_workbench_routes.__globals__["require_admin_dashboard_user"],
                 prompt_routes.login_required, prompt_routes.api_authenticate_only,
                 prompt_routes.require_admin_dashboard_user)
    for auth in {function.__globals__["AuthService"] for function in functions}:
        monkeypatch.setattr(auth, name, value)


@pytest.fixture
def client(monkeypatch):
    app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / "templates"))
    app.config.update(TESTING=True, SECRET_KEY="synthetic-session", WTF_CSRF_ENABLED=False)
    init_error_handlers(app)
    CSRFProtect(app)
    app.register_error_handler(CSRFError, handle_csrf_error)
    register_workbench_routes(app)
    user = {"username": "owner", "is_admin": True, "scopes": ["prompts:render"]}
    patch_auth(monkeypatch, "is_authenticated", lambda: True)
    patch_auth(monkeypatch, "get_current_user", lambda: user)
    patch_auth(monkeypatch, "verify_api_key", lambda key, ip: user if key == "synthetic-key" else None)
    audit = Mock()
    monkeypatch.setattr("services.audit_log.record", audit)
    return app, app.test_client(), user, audit


def enabled(monkeypatch):
    monkeypatch.setenv("PROMPT_TEMPLATES_ENABLED", "true")


def render(client, variables=None, version=1, slug="greeting"):
    return client.post(f"/v1/prompt-templates/{slug}/render", json={"version": version, "variables": variables or {"name": "Ada"}},
                       headers={"Authorization": "Bearer synthetic-key"})


def test_disabled_routes_precede_auth_csrf_storage_and_do_not_change_existing_routes(client, monkeypatch):
    app, browser, _, audit = client
    app.config["WTF_CSRF_ENABLED"] = True
    patch_auth(monkeypatch, "is_authenticated", Mock(side_effect=AssertionError("auth called")))
    monkeypatch.setattr(templates.PromptTemplateStore, "connection", Mock(side_effect=AssertionError("storage called")))
    for method, path in [("GET", "/admin/workbench/prompts"), ("POST", "/admin/workbench/prompts"),
                         ("POST", "/v1/prompt-templates/greeting/render"), ("OPTIONS", "/v1/prompt-templates/greeting/render")]:
        assert browser.open(path, method=method, json=TEMPLATE).status_code == 404
    audit.assert_not_called()
    app.config["WTF_CSRF_ENABLED"] = False
    patch_auth(monkeypatch, "is_authenticated", lambda: True)
    before = browser.get("/admin/workbench/profiles")
    enabled(monkeypatch)
    after = browser.get("/admin/workbench/profiles")
    assert before.data == after.data and dict(before.headers) == {**dict(after.headers), "X-Request-ID": before.headers["X-Request-ID"]}


def test_registered_paths_store_render_conflict_and_audit_content_free(client, monkeypatch, caplog):
    enabled(monkeypatch)
    _, browser, _, audit = client
    stored = browser.post("/admin/workbench/prompts", json=TEMPLATE)
    assert stored.status_code == 201
    expected = {**TEMPLATE, "content_hash": hashlib.sha256(TEMPLATE["content"].encode()).hexdigest()}
    assert stored.json == expected
    assert browser.post("/admin/workbench/prompts", json={**TEMPLATE, "content": "Changed {{name}}"}).status_code == 409
    assert browser.get("/admin/workbench/prompts", headers={"Accept": "application/json"}).json["templates"] == [expected]
    response = render(browser, {"name": "{{danger}} __import__(\"os\") \\1"})
    assert response.status_code == 200
    assert response.json == {"slug": "greeting", "version": 1, "content_hash": expected["content_hash"],
                             "rendered": "Hello {{danger}} __import__(\"os\") \\1 / {{danger}} __import__(\"os\") \\1"}
    assert response.headers["Cache-Control"] == "no-store"
    assert TEMPLATE["content"] not in caplog.text and "__import__" not in caplog.text
    assert audit.call_args_list
    assert TEMPLATE["content"] not in str(audit.call_args_list) and "__import__" not in str(audit.call_args_list)
    assert browser.post("/admin/workbench/prompts", json={**TEMPLATE, "version": 2}).status_code == 201
    assert render(browser, version=2).status_code == 200


def test_auth_scope_and_owner_isolation(client, monkeypatch):
    enabled(monkeypatch)
    _, browser, user, _ = client
    assert browser.post("/admin/workbench/prompts", json=TEMPLATE).status_code == 201
    user.update(username="other", is_admin=False, scopes=["chat"])
    assert render(browser).status_code == 403
    user["scopes"] = ["prompts:render"]
    assert render(browser).status_code == 404
    assert browser.get("/admin/workbench/prompts", headers={"Accept": "application/json"}).status_code == 403
    user["is_admin"] = True
    assert browser.get("/admin/workbench/prompts", headers={"Accept": "application/json"}).json["templates"] == []
    assert browser.post("/admin/workbench/prompts", json=TEMPLATE).status_code == 201
    assert render(browser).status_code == 200
    assert browser.post("/v1/prompt-templates/greeting/render", json={"version": 1, "variables": {"name": "Ada"}}).status_code == 401


def test_enabled_admin_requires_csrf_but_bearer_render_is_exempt(client, monkeypatch):
    enabled(monkeypatch)
    app, browser, _, _ = client
    assert browser.post("/admin/workbench/prompts", json=TEMPLATE).status_code == 201
    app.config["WTF_CSRF_ENABLED"] = True
    assert browser.post("/admin/workbench/prompts", json={**TEMPLATE, "version": 2}).status_code == 400
    assert render(browser).status_code == 200


@pytest.mark.parametrize("change", [{"version": True}, {"version": 0}, {"version": "1"}, {"slug": "../x"}, {"owner": "other"},
    {"content_hash": "bad"}, {"content": "{{name.upper()}}"}, {"content": "{{ name }}"}, {"content": "{{name"},
    {"content": "name}}"}, {"content": "{% include x %}"}, {"variables": ["name", "name"]}, {"variables": ["other"]},
    {"variables": {"name": "str"}}, {"variables": ["x"] * 33}, {"content": "😀" * 16385}])
def test_invalid_templates_are_rejected_before_storage(client, monkeypatch, change):
    enabled(monkeypatch)
    _, browser, _, _ = client
    save = Mock(side_effect=AssertionError("invalid data reached storage"))
    monkeypatch.setattr(templates.PromptTemplateStore, "create", save)
    assert browser.post("/admin/workbench/prompts", json={**TEMPLATE, **change}).status_code == 400
    save.assert_not_called()


@pytest.mark.parametrize("variables", [{}, {"name": "Ada", "extra": "x"}, {"name": 1}, {"name": []}, None])
def test_render_requires_exact_declared_string_variables(client, monkeypatch, variables):
    enabled(monkeypatch)
    _, browser, _, _ = client
    browser.post("/admin/workbench/prompts", json=TEMPLATE)
    assert browser.post("/v1/prompt-templates/greeting/render", json={"version": 1, "variables": variables},
                        headers={"Authorization": "Bearer synthetic-key"}).status_code == 400


def test_bounds_and_strict_fields(client, monkeypatch):
    enabled(monkeypatch)
    _, browser, _, _ = client
    content = "{{x}}" * (65536 // 5)
    value = {"slug": "large", "version": 1, "content": content, "variables": ["x"]}
    assert browser.post("/admin/workbench/prompts", json=value).status_code == 201
    assert render(browser, {"x": "x" * 100}, slug="large").status_code == 413
    assert render(browser, {"x": "😀" * 16385}, slug="large").status_code == 400
    assert browser.post("/admin/workbench/prompts", data="x" * 524289, content_type="application/json").status_code == 413
    assert render(browser, version=True).status_code == 400
    assert browser.post("/v1/prompt-templates/large/render", json={"variables": {}, "version": 1, "extra": 1},
                        headers={"Authorization": "Bearer synthetic-key"}).status_code == 400
    assert browser.get("/admin/workbench/prompts?owner=other", headers={"Accept": "application/json"}).status_code == 400


def test_sqlite_migration_keeps_old_rows_conflicts_atomically_and_survives_restarts():
    with templates.PromptTemplateStore.connection() as db:
        db.execute("CREATE TABLE old_records (value TEXT)")
        db.execute("INSERT INTO old_records VALUES (?)", ("old",))
    def save(_):
        try:
            templates.PromptTemplateStore.create("owner", TEMPLATE)
            return 201
        except APIError as error:
            return error.status_code
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(save, range(4)))
    assert sorted(outcomes) == [201, 409, 409, 409]
    assert templates.PromptTemplateStore.get("owner", "greeting", 1)["content"] == TEMPLATE["content"]
    assert templates.PromptTemplateStore.list("other")["templates"] == []
    with templates.PromptTemplateStore.connection() as db:
        assert db.execute("SELECT value FROM old_records").fetchone()["value"] == "old"


def test_sqlite_missing_table_fails_closed(client, monkeypatch):
    enabled(monkeypatch)
    _, browser, _, _ = client
    monkeypatch.setattr(templates.PromptTemplateStore, "ensure", lambda db: None)
    for response in (browser.get("/admin/workbench/prompts"), browser.post("/admin/workbench/prompts", json=TEMPLATE), render(browser)):
        assert response.status_code == 503 and response.json["error"] == "prompt_templates_storage_unavailable"


def test_retention_and_bounded_paginated_lists(monkeypatch):
    monkeypatch.setattr(templates.time, "time", lambda: 1000)
    for version in range(1, 5):
        templates.PromptTemplateStore.create("owner", {**TEMPLATE, "version": version})
    page = templates.PromptTemplateStore.list("owner")
    assert len(page["templates"]) == 2 and page["next"] == {"slug": "greeting", "version": 2}
    assert [row["version"] for row in templates.PromptTemplateStore.list("owner", page["next"])["templates"]] == [3, 4]
    monkeypatch.setattr(templates.time, "time", lambda: 1000 + templates.RETENTION_SECONDS)
    assert templates.PromptTemplateStore.list("owner")["templates"] == []
    with pytest.raises(APIError) as caught:
        templates.PromptTemplateStore.get("owner", "greeting", 1)
    assert caught.value.status_code == 404
    with pytest.raises(APIError) as caught:
        templates.PromptTemplateStore.create("owner", TEMPLATE)
    assert caught.value.status_code == 409, "expiration must never allow an immutable version to be reused"


def test_d1_uses_fixed_domain_no_fallback_and_validates_responses(monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    expected = {**TEMPLATE, "content_hash": hashlib.sha256(TEMPLATE["content"].encode()).hexdigest()}
    call = Mock(return_value={"version": 1, "template": expected})
    monkeypatch.setattr(templates, "d1_call", call)
    assert templates.PromptTemplateStore.get("owner", "greeting", 1) == expected
    assert call.call_args.args[0]["principal"] == "owner"
    call.return_value = {"version": 1, "template": {**expected, "content_hash": "a" * 64}}
    with pytest.raises(APIError) as caught:
        templates.PromptTemplateStore.get("owner", "greeting", 1)
    assert caught.value.status_code == 503
    for code, status in [("version_conflict", 409), ("storage_unavailable", 503)]:
        call.side_effect = templates.PrivateIntelligenceError(status, code)
        with pytest.raises(APIError) as caught:
            templates.PromptTemplateStore.create("owner", TEMPLATE)
        assert caught.value.status_code == status
    call.side_effect = None
    call.return_value = {"version": 1, "templates": [expected], "next": None}
    assert templates.PromptTemplateStore.list("owner")["templates"] == [expected]


def test_full_app_registers_routes_without_provider_calls(monkeypatch, tmp_path):
    import config
    monkeypatch.setattr(config, "load_runtime_env", lambda: None)
    monkeypatch.setenv("FLASK_SECRET_KEY", "synthetic-session-secret")
    monkeypatch.setenv("JWT_SECRET", "synthetic-jwt-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "owner")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-key")
    for name in ("USER_DB_PATH", "LOGIN_ATTEMPTS_DB_PATH", "RATE_LIMIT_DB_PATH", "MODEL_REGISTRY_DB_PATH"):
        monkeypatch.setenv(name, str(tmp_path / (name + ".sqlite3")))
    monkeypatch.setattr("env_loader.load_runtime_env", lambda: None)
    module = importlib.import_module("app")
    monkeypatch.setattr(module, "load_runtime_env", lambda: None)
    app = module.create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    browser = app.test_client()
    assert browser.get("/admin/workbench/prompts", headers={"Accept": "application/json"}).status_code == 404
    assert render(browser).status_code == 404
    enabled(monkeypatch)
    user = {"username": "owner", "is_admin": True, "scopes": ["prompts:render"]}
    monkeypatch.setattr("routes.core.AuthService.get_current_user", lambda: user)
    monkeypatch.setattr("route_helpers.AuthService.is_authenticated", lambda: True)
    monkeypatch.setattr("route_helpers.AuthService.verify_api_key", lambda key, ip: user)
    monkeypatch.setattr("services.audit_log.record", Mock())
    assert browser.post("/admin/workbench/prompts", json=TEMPLATE).status_code == 201
    assert browser.get("/admin/workbench/prompts").json["templates"][0]["slug"] == "greeting"
    assert render(browser).json["rendered"] == "Hello Ada / Ada"


def test_secret_policy_refuses_persistence_and_rendering_without_rewriting(client, monkeypatch):
    enabled(monkeypatch)
    _, browser, user, _ = client
    user["secret_scan_mode"] = "block"
    secret = "sk-" + "s" * 48
    value = {"slug": "secret", "version": 1, "content": "API key: " + secret, "variables": []}
    assert browser.post("/admin/workbench/prompts", json=value).status_code == 422
    assert browser.get("/admin/workbench/prompts", headers={"Accept": "application/json"}).json["templates"] == []
    assert browser.post("/admin/workbench/prompts", json=TEMPLATE).status_code == 201
    assert render(browser, {"name": secret}).status_code == 422


def test_owner_limit_and_invalid_backend_do_not_fall_back_to_local_storage(monkeypatch):
    for version in range(1, 101):
        templates.PromptTemplateStore.create("owner", {**TEMPLATE, "version": version})
    with pytest.raises(APIError) as caught:
        templates.PromptTemplateStore.create("owner", {**TEMPLATE, "version": 101})
    assert caught.value.status_code == 409
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "typo")
    with pytest.raises(APIError) as caught:
        templates.PromptTemplateStore.get("owner", "greeting", 1)
    assert caught.value.status_code == 503


@pytest.mark.parametrize("status,payload", [(200, {"version": 1, "stored": True}),
    (409, {"version": 1, "error": {"code": "version_conflict"}}),
    (503, {"version": 1, "error": {"code": "storage_unavailable"}}),
    (302, {"version": 1}), (200, {"version": True}), (200, {"version": 1, "error": {"code": "secret"}})])
def test_private_transport_is_fixed_single_submission_and_redacts_errors(monkeypatch, status, payload):
    import json
    response = Mock(status_code=status, headers={"Content-Type": "application/json"})
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.iter_content.return_value = [json.dumps(payload).encode()]
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.post.return_value = response
    monkeypatch.setattr(templates.requests, "Session", lambda: session)
    if status == 200 and payload == {"version": 1, "stored": True}:
        assert templates.d1_call({"operation": "create"}) == payload
    else:
        with pytest.raises((APIError, templates.PrivateIntelligenceError)):
            templates.d1_call({"operation": "create"})
    session.post.assert_called_once()
    assert session.post.call_args.args == ("http://intelligence.internal/v1/state/prompt-templates",)
    assert session.post.call_args.kwargs["allow_redirects"] is False
    assert session.post.call_args.kwargs["timeout"] == (2, 3)
    assert session.trust_env is False


def test_private_transport_refuses_oversized_and_duplicate_responses(monkeypatch):
    for data in (b"{\"version\":1,\"version\":1}", b"x" * (templates.MAX_RESPONSE_BYTES + 1)):
        response = Mock(status_code=200, headers={"Content-Type": "application/json"})
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.iter_content.return_value = [data]
        session = Mock()
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=False)
        session.post.return_value = response
        monkeypatch.setattr(templates.requests, "Session", lambda: session)
        with pytest.raises(APIError) as caught:
            templates.d1_call({"operation": "get"})
        assert caught.value.status_code == 503
        session.post.assert_called_once()



def test_enabled_d1_route_failures_are_503_with_no_sqlite_fallback(client, monkeypatch):
    enabled(monkeypatch)
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setattr(templates, "d1_call", Mock(side_effect=templates.PrivateIntelligenceError(503, "storage_unavailable")))
    local = Mock(side_effect=AssertionError("D1 failure fell back to SQLite"))
    monkeypatch.setattr(templates.PromptTemplateStore, "connection", local)
    _, browser, _, _ = client
    for response in (browser.get("/admin/workbench/prompts"),
                     browser.post("/admin/workbench/prompts", json=TEMPLATE), render(browser)):
        assert response.status_code == 503
        assert response.json["error"] == "prompt_templates_storage_unavailable"
    local.assert_not_called()



def test_stopped_private_submission_releases_its_slot_without_http():
    import queue
    import threading
    stopped, results = threading.Event(), queue.Queue(maxsize=1)
    stopped.set()
    assert templates._slots.acquire(blocking=False)
    templates._submit(b"{}", stopped, templates.time.monotonic() + 5, results)
    success, error = results.get_nowait()
    assert success is False and error.status_code == 503
    assert templates._slots.acquire(blocking=False)
    templates._slots.release()
