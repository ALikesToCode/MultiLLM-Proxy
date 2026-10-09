"""Registered tenant boundaries and atomic hierarchy storage with synthetic accounts."""
import importlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from flask import Flask, g, jsonify
from flask_wtf.csrf import CSRFProtect

from services import tenant_hierarchy as th


@pytest.fixture
def store(monkeypatch, tmp_path):
    monkeypatch.setenv("ORGANISATIONS_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    path = tmp_path / "auth.sqlite3"
    monkeypatch.setenv("AUTH_DB_PATH", str(path))
    with sqlite3.connect(path) as db:
        db.executescript((Path(__file__).resolve().parents[1] / "intelligence-migrations/0033_tenant_hierarchy.sql").read_text())
        db.execute("CREATE TABLE old_records (owner TEXT)")
        db.execute("INSERT INTO old_records VALUES ('alice')")
    return th.TenantStore(principal_exists=lambda principal: principal in {"alice", "bob", "operator"})


def hierarchy(store):
    org = store.request("org_create", actor="operator", data={"name": "Example"})
    team = store.request("team_create", actor="operator", org_id=org["id"], data={"name": "Support"})
    return org, team


def member(store, org, team=None, **data):
    return store.request("member_set", actor="operator", org_id=org["id"], principal="alice", revision=0,
                         data={"role": "member", "team_id": team["id"] if team else None, "status": "active", **data})


def test_disabled_is_legacy_and_does_not_touch_store(monkeypatch):
    for flag in ("", "false", "malformed-secret-value"):
        monkeypatch.setenv("ORGANISATIONS_ENABLED", flag)
        fake = Mock(side_effect=AssertionError("No storage"))
        context = th.resolve_principal("alice", store=Mock(request=fake))
        assert context == th.TenantContext("alice")
        assert th.tenant_namespace(context) == ""
        fake.assert_not_called()


def test_flag_warns_once_without_value(monkeypatch, caplog):
    th._warn_once.cache_clear()
    monkeypatch.setenv("ORGANISATIONS_ENABLED", "private-bad-value")
    assert not th.enabled() and not th.enabled()
    assert caplog.text.count("Invalid ORGANISATIONS_ENABLED") == 1
    assert "private-bad-value" not in caplog.text


def test_ids_are_generated_and_schema_is_additive(store):
    org, team = hierarchy(store)
    assert org["id"] != team["id"] and org["revision"] == team["revision"] == 1
    with pytest.raises(th.TenantError) as error:
        store.request("org_create", actor="operator", data={"name": "Other", "id": org["id"]})
    assert error.value.status == 400
    with sqlite3.connect(th.storage_path("AUTH_DB_PATH", "auth.sqlite3")) as db:
        assert db.execute("SELECT owner FROM old_records").fetchone()[0] == "alice"
        assert db.execute("SELECT count(*) FROM tenant_bindings").fetchone()[0] == 0


def test_binding_is_explicit_and_membership_isolated(store):
    org, team = hierarchy(store)
    member(store, org, team)
    assert th.resolve_principal("alice", store=store).org_id is None
    assert store.request("workspaces", principal="bob")["memberships"] == []
    binding = store.request("binding_set", actor="alice", principal="alice", revision=0,
                            data={"org_id": org["id"], "team_id": team["id"]})
    assert binding["revision"] == 1
    context = th.resolve_principal("alice", store=store)
    assert th.tenant_namespace(context) == f"org:{org['id']}/team:{team['id']}"
    assert store.request("workspaces", principal="alice")["binding"] == binding
    with pytest.raises(th.TenantError, match="workspace_forbidden"):
        store.request("binding_set", actor="bob", principal="bob", revision=0,
                      data={"org_id": org["id"], "team_id": team["id"]})


def test_foreign_team_missing_and_revoked_binding_fail_closed(store):
    org, team = hierarchy(store)
    other, foreign = hierarchy(store)
    with pytest.raises(th.TenantError, match="workspace_not_found"):
        member(store, org, foreign)
    member(store, org, team, bind=True, binding_revision=0)
    before = th.resolve_principal("alice", store=store)
    store.request("member_set", actor="operator", org_id=org["id"], principal="alice", revision=1,
                  data={"status": "deactivated"})
    with pytest.raises(th.TenantError, match="workspace_forbidden"):
        th.resolve_principal("alice", store=store)
    store.request("member_set", actor="operator", org_id=org["id"], principal="alice", revision=2,
                  data={"status": "active"})
    assert th.resolve_principal("alice", store=store).grants_revision > before.grants_revision
    store.request("team_update", actor="operator", org_id=org["id"], team_id=team["id"], revision=1,
                  data={"status": "deactivated"})
    with pytest.raises(th.TenantError, match="workspace_forbidden"):
        th.resolve_principal("alice", store=store)
    with sqlite3.connect(th.storage_path("AUTH_DB_PATH", "auth.sqlite3")) as db:
        db.execute("UPDATE tenant_bindings SET team_id='missing' WHERE principal='alice'")
    with pytest.raises(th.TenantError, match="workspace_not_found"):
        th.resolve_principal("alice", store=store)


def test_cas_one_winner_and_content_free_audit(store):
    org, _ = hierarchy(store)
    def write(name):
        try:
            return store.request("org_update", actor="operator", org_id=org["id"], revision=1, data={"name": name})
        except th.TenantError as error:
            return error.status
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, ["confidential-one", "confidential-two"]))
    assert sum(isinstance(result, dict) for result in results) == 1 and 412 in results
    with sqlite3.connect(th.storage_path("AUTH_DB_PATH", "auth.sqlite3")) as db:
        rows = db.execute("SELECT * FROM tenant_audit").fetchall()
        assert len(rows) == 3
        assert "confidential" not in repr(rows)


def test_caps_and_unknown_principals(store):
    org, team = hierarchy(store)
    with sqlite3.connect(th.storage_path("AUTH_DB_PATH", "auth.sqlite3")) as db:
        db.executemany("INSERT INTO tenant_teams VALUES (?, ?, ?, 'deactivated', 1)",
                       [(f"team_{i}", org["id"], "Example") for i in range(99)])
        db.executemany("INSERT INTO tenant_memberships VALUES (?, ?, NULL, 'member', 'deactivated', 1)",
                       [(org["id"], f"principal_{i}") for i in range(1000)])
    with pytest.raises(th.TenantError, match="tenant_limit_reached"):
        store.request("team_create", actor="operator", org_id=org["id"], data={"name": "Extra"})
    with pytest.raises(th.TenantError, match="tenant_limit_reached"):
        member(store, org)
    with pytest.raises(th.TenantError, match="principal_not_found"):
        store.request("member_set", actor="operator", org_id=org["id"], principal="unknown", revision=0,
                      data={"role": "member"})


@pytest.fixture
def registered(store, monkeypatch):
    routes = importlib.import_module("routes.tenants")
    registrar = importlib.import_module("services.gateway_extensions")
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="synthetic-tenant-session", WTF_CSRF_ENABLED=False)
    csrf = CSRFProtect(app)
    routes.register_tenant_routes(app, csrf=csrf, store=store)
    registrar.register_tenants(app)
    auth = importlib.import_module("services.auth_service").AuthService
    monkeypatch.setattr(auth, "is_authenticated", lambda: True)
    monkeypatch.setattr(auth, "get_current_user", lambda: {"username": "operator", "is_admin": True})
    monkeypatch.setattr(auth, "verify_api_key", lambda *_: {"username": "alice", "scopes": ["models", "chat"]})
    for guard in (routes.login_required, routes.api_authenticate_only, routes.require_admin_dashboard_user):
        monkeypatch.setitem(guard.__globals__, "AuthService", auth)
    monkeypatch.setattr(routes.api_authenticate_only.__globals__["request_accounting"],
                        "check_key_controls", lambda *_: None)
    @app.get("/probe")
    def probe():
        g.authenticated_user = {"username": "alice"}
        refused = registrar.after_authentication()
        return refused if refused is not None else jsonify(namespace=th.tenant_namespace())
    return app, app.test_client(), auth, registrar


def test_registered_disabled_routes_precede_auth_csrf_and_json(registered, monkeypatch):
    app, client, auth, _ = registered
    app.config["WTF_CSRF_ENABLED"] = True
    monkeypatch.setattr(auth, "is_authenticated", Mock(side_effect=AssertionError("No authentication")))
    monkeypatch.setenv("ORGANISATIONS_ENABLED", "")
    for path in ("/admin/organisations", "/admin/organisations/absent", "/admin/organisations/absent/teams",
                 "/admin/organisations/absent/teams/absent", "/admin/organisations/absent/members",
                 "/admin/organisations/absent/members/alice", "/v1/workspaces", "/v1/workspaces/switch"):
        for method in ("GET", "POST", "PATCH", "PUT"):
            result = client.open(path, method=method, data="not json")
            assert result.status_code == 404 and result.is_json
            assert result.headers["Cache-Control"] == "no-store"


def test_registered_admin_cas_guards_and_csrf(registered, monkeypatch):
    app, client, auth, _ = registered
    org = client.post("/admin/organisations", json={"name": "Example"}).json
    assert org["revision"] == 1
    path = f"/admin/organisations/{org['id']}"
    assert client.patch(path, json={"name": "Next"}).status_code == 428
    assert client.patch(path, json={"name": "Next"}, headers={"If-Match": '"0"'}).status_code == 412
    response = client.patch(path, json={"name": "Next"}, headers={"If-Match": '"1"'})
    assert response.json["revision"] == 2 and response.headers["ETag"] == '"2"'
    monkeypatch.setattr(auth, "get_current_user", lambda: {"username": "operator", "is_admin": False})
    assert client.get(path).status_code == 403
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/admin/organisations", json={"name": "Example"}).status_code == 400


def test_workspace_switch_and_spoofing_registered(registered, store):
    _, client, _, registrar = registered
    org, team = hierarchy(store)
    member(store, org, team)
    headers = {"Authorization": "Bearer synthetic", "X-Org": org["id"], "X-Team": team["id"],
               "X-MultiLLM-Workspace": org["id"]}
    assert client.get("/probe", headers=headers).json == {"namespace": ""}
    assert client.get("/v1/workspaces", headers=headers).json["memberships"][0]["org_id"] == org["id"]
    response = client.post("/v1/workspaces/switch", headers={**headers, "If-Match": '"0"'},
                           json={"org_id": org["id"], "team_id": team["id"]})
    assert response.status_code == 200
    assert client.get("/probe", headers={"X-Org": "foreign"}).json["namespace"] == th.tenant_namespace(th.resolve_principal("alice", store=store))
    assert registrar.AUTHENTICATED_HOOK_ORDER[0] == "tenant_context_hook"


def test_missing_schema_and_private_errors_are_json_503(registered, monkeypatch, tmp_path):
    _, client, _, _ = registered
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "missing.sqlite3"))
    response = client.get("/probe")
    assert response.status_code == 503 and response.json["error"]["code"] == "tenant_storage_unavailable"
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    fake = Mock(return_value={"version": 1, "error": {"code": "workspace_forbidden"}, "status": 403})
    remote = th.TenantStore(call=fake)
    with pytest.raises(th.TenantError, match="workspace_forbidden"):
        th.resolve_principal("alice", store=remote)
    assert fake.call_count == 1


def test_registered_tenant_failure_stops_later_hooks_and_metadata(registered, store, monkeypatch):
    app, client, auth, registrar = registered
    org, team = hierarchy(store)
    member(store, org, team, bind=True, binding_revision=0)
    store.request("org_update", actor="operator", org_id=org["id"], revision=1, data={"status": "deactivated"})
    later = Mock(side_effect=AssertionError("No downstream storage or provider"))
    later.__name__ = "request_policy_hook"
    registrar.register_authenticated_hook(app, later)
    response = client.get("/probe")
    assert response.status_code == 403 and response.json["error"]["code"] == "workspace_forbidden"
    later.assert_not_called()
    monkeypatch.setattr(auth, "_users", {"alice": {"last_used_at": None}})
    with app.test_request_context("/probe"):
        with pytest.raises(th.TenantError, match="workspace_forbidden"):
            auth._update_key_usage("alice")
    assert auth._users["alice"]["last_used_at"] is None


def test_binding_cas_and_admin_binding_are_atomic(store):
    org, team = hierarchy(store)
    member(store, org, team, bind=True, binding_revision=0)
    with pytest.raises(th.TenantError, match="revision_conflict"):
        store.request("member_set", actor="operator", org_id=org["id"], principal="alice", revision=1,
                      data={"role": "billing", "bind": True, "binding_revision": 0})
    assert store.request("member_list", org_id=org["id"])["members"][0]["role"] == "member"
    with pytest.raises(th.TenantError, match="revision_conflict"):
        store.request("binding_set", actor="alice", principal="alice", revision=0,
                      data={"org_id": org["id"], "team_id": team["id"]})


def test_create_app_mounts_routes_with_no_live_side_effects(store, monkeypatch):
    for name, value in {"FLASK_SECRET_KEY": "synthetic-tenant-session", "JWT_SECRET": "synthetic-tenant-jwt",
                        "ADMIN_API_KEY": "synthetic-tenant-admin", "CONFIG_REVISION_SYNC_ENABLED": "false"}.items():
        monkeypatch.setenv(name, value)
    with patch("config.load_runtime_env"), patch("env_loader.load_runtime_env"), \
            patch("requests.sessions.Session.send", side_effect=AssertionError("No network")):
        module = importlib.import_module("app")
        with patch.object(module, "load_runtime_env"), patch.object(module.AuthService, "initialize"), patch.object(module.usage_ledger, "start"):
            app = module.create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    app.extensions["tenant_store"] = store
    with patch.object(module.AuthService, "is_authenticated", return_value=True), \
            patch.object(module.AuthService, "get_current_user", return_value={"username": "operator", "is_admin": True}):
        response = app.test_client().post("/admin/organisations", json={"name": "Registered"})
    assert response.status_code == 201
    assert app.extensions["gateway_after_authentication"][0].__name__ == "tenant_context_hook"


@pytest.mark.parametrize("data", [{"role": None}, {"role": ["admin"]}, {"status": None}, {"status": ["active"]}, {"bind": "true"}])
def test_membership_invalid_types_are_rejected_without_mutation(store, data):
    org, _ = hierarchy(store)
    with pytest.raises(th.TenantError) as error:
        member(store, org, **data)
    assert error.value.status == 400
    assert store.request("member_list", org_id=org["id"])["members"] == []


def test_registered_full_admin_lifecycle_and_workspace_scope(registered, store, monkeypatch):
    _, client, auth, _ = registered
    org = client.post("/admin/organisations", json={"name": "Example"}).json
    base = f"/admin/organisations/{org['id']}"
    team = client.post(base + "/teams", json={"name": "Support"}).json
    assert client.get(base + "/teams").json["teams"] == [team]
    response = client.put(base + "/members/alice", headers={"If-Match": '\"0\"'},
                          json={"role": "billing", "team_id": team["id"], "status": "active"})
    assert response.status_code == 200
    assert client.get(base + "/members").json["members"] == [response.json]
    assert client.patch(base + f"/teams/{team['id']}", headers={"If-Match": '\"1\"'}, json={"name": "Renamed"}).status_code == 200
    assert client.post("/v1/workspaces/switch", headers={"Authorization": "Bearer synthetic"},
                       json={"org_id": org["id"], "team_id": team["id"]}).status_code == 428
    monkeypatch.setattr(auth, "verify_api_key", lambda *_: {"username": "bob", "scopes": ["chat"]})
    assert client.get("/v1/workspaces", headers={"Authorization": "Bearer synthetic"}).status_code == 403


def test_account_tenant_check_follows_matching_hash_and_cached_verification(monkeypatch):
    module = importlib.import_module("services.auth_service")
    auth = module.AuthService
    key = "shared01-synthetic-matching"
    users = {"alice": {"api_key_hash": "other", "revoked_at": None},
             "bob": {"api_key_hash": "matching", "revoked_at": None}}
    checks = []
    monkeypatch.setenv("ADMIN_API_KEY", "")
    monkeypatch.setattr(auth, "_users", users)
    monkeypatch.setattr(auth, "_verified_keys", {})
    monkeypatch.setattr(auth, "_load_users_by_api_key_prefix", lambda _: list(users.items()))
    monkeypatch.setattr(auth, "_public_user", lambda username, _: {"username": username})
    monkeypatch.setattr(module.key_controls, "verify_revisioned_key", lambda *_: module.key_controls.LEGACY_AUTH)
    monkeypatch.setattr(module.user_store, "using_d1", lambda: True)
    touch = Mock()
    monkeypatch.setattr(module.user_store, "touch_user", touch)

    def check_hash(stored, provided):
        checks.append(("hash", stored, provided))
        return stored == "matching" and provided == key

    def verify_tenant(principal):
        checks.append(("tenant", principal))
        assert principal == "bob"

    monkeypatch.setattr(module, "check_password_hash", check_hash)
    monkeypatch.setattr(th, "verify_before_key_usage", verify_tenant)
    assert auth.verify_api_key(key) == {"username": "bob"}
    assert checks == [("hash", "other", key), ("hash", "matching", key), ("tenant", "bob")]
    checks.clear()
    assert auth.verify_api_key(key) == {"username": "bob"}
    assert checks == [("tenant", "bob")]
    checks.clear()
    assert auth.verify_api_key("shared01-wrong-key") is None
    assert all(check[0] == "hash" for check in checks)
    assert touch.call_count == 1
    assert touch.call_args.args[0] == "bob"


def test_bootstrap_tenant_check_follows_environment_key_verification(monkeypatch):
    module = importlib.import_module("services.auth_service")
    auth = module.AuthService
    monkeypatch.setenv("ADMIN_USERNAME", "operator")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-bootstrap")
    monkeypatch.setattr(auth, "_verified_keys", {})
    monkeypatch.setattr(auth, "_load_users_by_api_key_prefix", lambda _: [])
    monkeypatch.setattr(module.key_controls, "verify_revisioned_key", lambda *_: module.key_controls.LEGACY_AUTH)
    tenant = Mock()
    verified = Mock(return_value={"username": "operator"})
    monkeypatch.setattr(th, "verify_before_key_usage", tenant)
    monkeypatch.setattr(auth, "_verify_bootstrap_admin", verified)
    assert auth.verify_api_key("synthetic-bootstrap-wrong") is None
    tenant.assert_not_called()
    verified.assert_not_called()
    assert auth.verify_api_key("synthetic-bootstrap") == {"username": "operator"}
    tenant.assert_called_once_with("operator")
    verified.assert_called_once_with("operator", "synthetic-bootstrap", None)



def test_real_account_lookup_precedes_membership_write_transaction(store, monkeypatch):
    auth = importlib.import_module("services.auth_service").AuthService
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "")
    with auth._connect() as db:
        auth._ensure_users_schema(db)
        db.execute("INSERT INTO users (username,api_key_hash,api_key_prefix,scopes,is_admin,created_at) VALUES (?,?,?,?,?,?)",
                   ("alice", "synthetic-hash", "synthetic", '["chat"]', 0, "2026-10-09"))
    real_store = th.TenantStore()
    org, team = hierarchy(real_store)
    assert member(real_store, org, team)["principal"] == "alice"


def test_account_names_outside_the_opaque_format_keep_their_workspace(monkeypatch):
    from services import media_signing, tenant_governance
    from services.budget_service import principal_owner
    name = "alice@example.com"
    legacy = th._legacy(name)
    assert th.principal_id("alice") == "alice"
    assert th.principal_id(name) == legacy.principal_id and legacy.principal_id.startswith("principal:")
    workspace = th.TenantContext(legacy.principal_id, "org1", "team1")
    monkeypatch.setenv("ORGANISATIONS_ENABLED", "true")
    monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "true")
    monkeypatch.setenv("MEDIA_SIGNING_SECRET", "synthetic-signing-secret")
    app = Flask(__name__)
    tenant_governance.register_governance_collaborators(tenant_resolver=lambda user: workspace, app=app)
    with app.test_request_context("/v1/chat/completions"):
        g.tenant_context = workspace
        user = {"username": name}
        assert tenant_governance.workspace_context(user) == workspace
        assert principal_owner(user) != name
        token = media_signing.issue_principal("batch", "job1", name, 60)
        claims = media_signing.read_principal(token, "batch")
    with app.test_request_context("/internal/batch"):
        assert media_signing.bind_principal_tenant(claims, {"username": name}) == workspace
        assert g.tenant_context == workspace
