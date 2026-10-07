"""Synthetic admin journeys, confirmation guards and content-free responses."""
import importlib
import sys
import pytest
from unittest.mock import Mock
from tests.test_shadow_eval import sample, result
from tests.test_intelligence_policy import candidate, policy
from services.shadow_eval_store import ShadowEvalStore as Store
from services.intelligence_store import IntelligenceStore

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setenv("INTELLIGENCE_REQUIRE_DURABLE_STORAGE", "false")
    for name in ("AUTH_DB_PATH", "MODEL_REGISTRY_DB_PATH", "RATE_LIMIT_DB_PATH", "CONNECTION_PROFILES_DB_PATH"):
        monkeypatch.setenv(name, str(tmp_path / (name + ".sqlite3")))
    for name, value in {"ADMIN_USERNAME": "shadow-admin", "ADMIN_API_KEY": "synthetic-shadow-key", "FLASK_SECRET_KEY": "synthetic-flask", "JWT_SECRET": "synthetic-jwt"}.items():
        monkeypatch.setenv(name, value)
    for name in ("app", "route_helpers", "services.auth_service", "routes.core", "routes.workbench", "routes.shadow_eval"):
        sys.modules.pop(name, None)
    app = importlib.import_module("app").create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    with app.test_client() as browser:
        assert browser.post("/login", data={"username": "shadow-admin", "api_key": "synthetic-shadow-key"}).status_code == 302
        yield app, browser


def test_admin_config_text_privacy_csrf_and_purge(client):
    app, browser = client
    old = browser.get("/admin/workbench/shadow/config").json
    assert old["enabled"] is False
    value = sample()
    Store.put(value)
    page = browser.get("/workbench")
    assert page.status_code == 200 and b'Model league' in page.data
    assert b'Synthetic answer' not in page.data and b'synthetic-shadow-key' not in page.data
    for path in ("league", "samples"):
        response = browser.get("/admin/workbench/shadow/" + path)
        assert response.status_code == 200
        assert b'Synthetic answer' not in response.data and b'Synthetic greeting' not in response.data
        assert response.headers["Cache-Control"] == "no-store"
    assert browser.get("/admin/workbench/shadow/samples/" + value["id"]).json["production_answer"]["content"] == "Synthetic answer"
    assert browser.get("/admin/workbench/shadow/samples/bad").status_code == 400
    app.config["WTF_CSRF_ENABLED"] = True
    assert browser.post("/admin/workbench/shadow/config", json={"config": old, "expected": old}).status_code == 400
    app.config["WTF_CSRF_ENABLED"] = False
    new = {**old, "enabled": True}
    assert browser.post("/admin/workbench/shadow/config", json={"config": new, "expected": old}).status_code == 200
    assert browser.post("/admin/workbench/shadow/config", json={"config": old, "expected": old}).status_code == 400
    assert browser.post("/admin/workbench/shadow/purge", json={}).status_code == 400
    assert browser.post("/admin/workbench/shadow/purge", json={"confirm": True}).json == {"purged": True}
    assert browser.get("/admin/workbench/shadow/samples/" + value["id"]).status_code == 404
    with browser.session_transaction() as session:
        session.clear()
    for path in ("league", "samples", "config", "samples/" + value["id"]):
        assert browser.get("/admin/workbench/shadow/" + path).status_code == 302


def test_admin_revalidation_and_run_authentication(client, monkeypatch):
    _, browser = client
    start = Mock(return_value=True)
    monkeypatch.setattr("routes.shadow_eval.start_run", start)
    assert browser.post("/admin/shadow-eval/run", json={}).status_code == 401
    headers = {"Authorization": "Bearer synthetic-shadow-key"}
    assert browser.post("/admin/shadow-eval/run", headers=headers, json={}).json["started"] is False
    old = Store.config()
    Store.save_config({**old, "enabled": True}, old)
    assert browser.post("/admin/shadow-eval/run", headers=headers, json={}).status_code == 202
    assert start.call_count == 1
    from services.sqlite_store import connect, storage_path
    with connect(storage_path("AUTH_DB_PATH", "auth.sqlite3")) as connection:
        connection.execute("UPDATE users SET is_admin = 0 WHERE username = ?", ("shadow-admin",))
    assert browser.get("/admin/workbench/shadow/samples").status_code == 403


def test_apply_requires_confirmation_revision_validation_and_backup(client, monkeypatch):
    _, browser = client
    base = policy(candidates=[candidate("openai:candidate"), candidate("openai:production")])
    IntelligenceStore.seed(base)
    monkeypatch.setattr(Store, "results", lambda: [result(str(index)) for index in range(20)])
    proposed = browser.post("/admin/workbench/shadow/propose", json={}).json
    assert proposed["policy_diff"]
    assert browser.post("/admin/workbench/shadow/apply", json={"revision": proposed["revision"]}).status_code == 400
    assert browser.post("/admin/workbench/shadow/apply", json={"confirm": True, "revision": "stale"}).status_code == 409
    assert IntelligenceStore.policy() == base
    response = browser.post("/admin/workbench/shadow/apply", json={"confirm": True, "revision": proposed["revision"]})
    assert response.status_code == 200 and response.json == {"applied": True, "auto_routes_applied": False}
    assert IntelligenceStore.policy() != base
