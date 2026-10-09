"""SCIM lifecycle through registered bearer routes with isolated authorities."""
import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from flask import Flask, Response
from flask_wtf.csrf import CSRFProtect

from services import scim_provisioning as scim
from services import user_provisioning as provisioning
from routes.scim import register_scim_routes


class Store:
    def __init__(self):
        self.rows = {}
        self.accounts = {}
        self.audit = []
        self.lock = threading.RLock()
        self.available = True

    def probe(self):
        if not self.available:
            raise scim.ScimError(503, "Storage unavailable")

    def list(self, org, kind, attribute=None, value=None, start=1, count=100):
        rows = [copy.deepcopy(row) for (tenant, resource_kind, _), row in self.rows.items()
                if tenant == org and resource_kind == kind]
        rows.sort(key=lambda row: row["id"])
        if attribute:
            rows = [row for row in rows if row.get(attribute) == value]
        return rows[start - 1:start - 1 + count], len(rows)

    def get(self, org, kind, resource_id):
        return copy.deepcopy(self.rows.get((org, kind, resource_id)))

    def account(self, username):
        return copy.deepcopy(self.accounts.get(username))

    def put(self, org, kind, resource, expected, account=None, token_digest=None, deactivate=False):
        with self.lock:
            self.probe()
            key = (org, kind, resource["id"])
            old = self.rows.get(key)
            if expected == 0:
                for (tenant, resource_kind, _), row in self.rows.items():
                    if tenant == org and resource_kind == kind:
                        if resource.get("externalId") and row.get("externalId") == resource["externalId"]:
                            return copy.deepcopy(row), False
                        if kind == "Users" and row["userName"] == resource["userName"]:
                            raise scim.ScimError(409, "Duplicate userName", "uniqueness")
                if account and account["username"] in self.accounts:
                    raise scim.ScimError(409, "Duplicate account", "uniqueness")
            elif not old or scim.revision(old) != expected:
                raise scim.ScimError(412, "Stale version", "invalidVers")
            self.rows[key] = copy.deepcopy(resource)
            if account:
                self.accounts[account["username"]] = copy.deepcopy(account)
            self.audit.append((org, kind, resource["id"], expected + 1))
            return copy.deepcopy(resource), expected == 0


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_USERNAMES", "")
    monkeypatch.setenv("SCIM_ENABLED", "true")
    monkeypatch.setenv("SCIM_TRUST_CONFIG_JSON", json.dumps({"tenants": {
        "org:a": {"token_ref": "SCIM_TEST_A"}, "org:b": {"token_ref": "SCIM_TEST_B"}}}))
    monkeypatch.setenv("SCIM_TEST_A", "synthetic-scim-a")
    monkeypatch.setenv("SCIM_TEST_B", "synthetic-scim-b")
    auth = Mock()
    auth._load_user_by_username.return_value = None
    auth._generate_api_key.return_value = "synthetic-discarded-key"
    store = Store()
    authority = Mock(side_effect=lambda operation: operation.context)
    service = scim.ScimService(store, auth, tenant_authority=authority)
    app = Flask(__name__)
    app.secret_key = "synthetic-csrf"
    CSRFProtect(app)
    app.add_url_rule("/raw", view_func=lambda: Response(b"unchanged", headers={"X-Raw": "same"}))
    register_scim_routes(app, service=service)
    return app.test_client(), store, auth, authority


def call(client, method, path="Users", body=None, tenant="a", **headers):
    return client.open("/scim/v2/" + path, method=method, json=body,
                       headers={"Authorization": "Bearer synthetic-scim-" + tenant, **headers})


def user(client, username="alice", external="subject-a", **changes):
    return call(client, "POST", body={"schemas": [scim.USER_SCHEMA], "userName": username,
                                     "externalId": external, **changes})


@pytest.mark.parametrize("flag", ["", "false", "0", "off", "bad-private-value"])
def test_disabled_all_paths_precede_auth_and_storage(setup, monkeypatch, flag):
    client, store, auth, _ = setup
    monkeypatch.setenv("SCIM_ENABLED", flag)
    store.available = False
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        assert client.open("/scim/v2/unknown", method=method).status_code == 404
    assert client.get("/raw").data == b"unchanged"
    auth._load_user_by_username.assert_not_called()


def test_flag_warns_once_without_value(caplog):
    scim._warn_once.cache_clear()
    assert not scim.enabled({})
    for _ in range(2):
        assert not scim.enabled({"SCIM_ENABLED": "private-invalid"})
    assert caplog.text.count("Invalid SCIM_ENABLED") == 1
    assert "private-invalid" not in caplog.text


def test_auth_scope_discovery_and_csrf_exemption(setup):
    client, _, _, _ = setup
    for headers in ({}, {"Authorization": "Bearer unknown"}, {"Authorization": "Basic x"}):
        response = client.get("/scim/v2/Users", headers=headers)
        assert response.status_code == 401
        assert response.json["schemas"] == [scim.ERROR_SCHEMA]
        assert response.json["status"] == "401"
        assert response.mimetype == "application/scim+json"
    for endpoint in ("ServiceProviderConfig", "Schemas", "ResourceTypes"):
        assert call(client, "GET", endpoint).status_code == 200
    assert call(client, "GET", "Schemas/" + scim.USER_SCHEMA).status_code == 200
    response = user(client)
    assert response.status_code == 201
    assert response.headers["ETag"] == response.json["meta"]["version"]
    assert response.headers["Location"].endswith("/Users/" + response.json["id"])
    assert "synthetic-discarded-key" not in response.get_data(as_text=True)
    assert call(client, "GET", "Users/" + response.json["id"], tenant="b").status_code == 404


def test_idempotency_uniqueness_default_scopes_and_no_admin(setup):
    client, store, auth, _ = setup
    first = user(client)
    repeat = user(client, username="renamed")
    assert repeat.status_code == 200 and repeat.json == first.json
    assert len(store.accounts) == len(store.audit) == 1
    account = store.accounts["alice"]
    assert account["is_admin"] == 0 and account["scopes"] == "chat,models"
    auth._require_admin.assert_not_called()
    assert user(client, external="other").status_code == 409
    assert user(client, username="admin", external="admin").status_code == 400
    for changes in ({"is_admin": True}, {"roles": [{"value": "admin"}]}, {"scopes": ["admin"]}):
        assert user(client, username="evil", external="evil", **changes).status_code == 400
    for kwargs in ({"is_admin": True}, {"scopes": ["admin"]}, {"scopes": ["knowledge:manage"]}):
        with pytest.raises(Exception):
            provisioning.provision_scim_user(auth, "evil", **kwargs)


def test_patch_etag_deactivate_reactivate_preserves_history(setup):
    client, store, auth, _ = setup
    created = user(client)
    path = "Users/" + created.json["id"]
    old_account = copy.deepcopy(store.accounts["alice"])
    patch = {"schemas": [scim.PATCH_SCHEMA], "Operations": [
        {"op": "replace", "path": "displayName", "value": "Alice"},
        {"op": "add", "path": "emails", "value": [{"value": "a@example.test", "primary": True}]},
        {"op": "replace", "path": "active", "value": False}]}
    auth._generate_api_key.return_value = "changed-synthetic-discarded-key"
    changed = call(client, "PATCH", path, patch, **{"If-Match": created.headers["ETag"]})
    assert changed.status_code == 200 and changed.json["active"] is False
    assert store.accounts["alice"]["revoked_at"]
    assert store.accounts["alice"]["api_key_prefix"] != old_account["api_key_prefix"]
    assert store.accounts["alice"]["created_at"] == old_account["created_at"]
    for method in ("PUT", "PATCH", "DELETE"):
        assert call(client, method, path, patch, **{"If-Match": created.headers["ETag"]}).status_code == 412
    prefix = store.accounts["alice"]["api_key_prefix"]
    on = {"schemas": [scim.PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": True}]}
    assert call(client, "PATCH", path, on).status_code == 200
    assert store.accounts["alice"]["api_key_prefix"] == prefix
    assert store.accounts["alice"]["revoked_at"] is None
    assert call(client, "DELETE", path).status_code == 204
    assert call(client, "GET", path).json["externalId"] == "subject-a"
    assert len(store.accounts) == 1


def test_filter_pagination_and_strict_validation(setup):
    client, _, _, _ = setup
    user(client)
    for expression in ('userName eq "alice"', 'externalId eq "subject-a"', 'displayName eq "missing"'):
        response = call(client, "GET", "Users?filter=" + expression + "&count=101")
        assert response.status_code == 200 and response.json["itemsPerPage"] <= 100
    for query in ("filter=active eq true", "filter=userName co alice", "startIndex=0", "count=-1", "count=bad"):
        assert call(client, "GET", "Users?" + query).status_code == 400
    assert call(client, "GET", "Users?count=0").json["Resources"] == []
    for changes in ({"schemas": ["unknown"]}, {"active": "false"}, {"name": {"unknown": "x"}},
                    {"emails": [{"value": "x", "unknown": True}]}):
        assert user(client, **changes).status_code == 400
    path = "Users/" + user(client).json["id"]
    for operation in ({"op": "move", "path": "active", "value": True},
                      {"op": "replace", "path": "roles", "value": []},
                      {"op": "replace", "path": "userName", "value": "bob"}):
        assert call(client, "PATCH", path, {"schemas": [scim.PATCH_SCHEMA], "Operations": [operation]}).status_code == 400


def test_groups_authority_members_and_patch_are_scoped(setup):
    client, store, _, authority = setup
    member = user(client).json["id"]
    foreign = call(client, "POST", body={"userName": "bob", "externalId": "foreign"}, tenant="b").json["id"]
    payload = {"schemas": [scim.GROUP_SCHEMA], "displayName": "engineering", "externalId": "team-a",
               "members": [{"value": member}]}
    created = call(client, "POST", "Groups", payload)
    assert created.status_code == 201
    assert authority.call_args[0][0].context.org_id == "org:a"
    path = "Groups/" + created.json["id"]
    for value in (foreign, "unknown"):
        bad = {"schemas": [scim.PATCH_SCHEMA], "Operations": [{"op": "add", "path": "members", "value": [{"value": value}]}]}
        assert call(client, "PATCH", path, bad).status_code == 400
    removed = {"schemas": [scim.PATCH_SCHEMA], "Operations": [{"op": "remove", "path": 'members[value eq "' + member + '"]'}]}
    assert call(client, "PATCH", path, removed).json["members"] == []
    assert call(client, "PUT", path, {"displayName": "renamed", "members": []}).status_code == 200
    assert call(client, "DELETE", path).status_code == 204
    assert len(store.rows) == 3
    authority.side_effect = lambda operation: scim.TenantContext("foreign", "org:b")
    assert call(client, "POST", "Groups", payload).status_code == 403


def test_missing_schema_and_authority_precede_account_changes(setup):
    client, store, auth, authority = setup
    store.available = False
    response = user(client)
    assert response.status_code == 503 and response.json["status"] == "503"
    auth._generate_api_key.assert_not_called()
    assert not store.accounts
    store.available = True
    authority.side_effect = scim.AuthorityDenied("unavailable")
    assert call(client, "POST", "Groups", {"displayName": "team"}).status_code == 503
    assert not store.rows


def test_atomic_duplicate_create_and_stale_updates(setup):
    _, store, auth, _ = setup
    service = scim.ScimService(store, auth, tenant_authority=lambda op: op.context)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: service.create("org:a", "Users", {"userName": "alice", "externalId": "a"}), range(2)))
    assert results[0][0]["id"] == results[1][0]["id"]
    assert len(store.accounts) == 1


def test_trust_config_ambiguity_and_invalid_values_fail_closed(monkeypatch):
    env = {"SCIM_TRUST_CONFIG_JSON": json.dumps({"tenants": {"org:a": {"token_ref": "A"}, "org:b": {"token_ref": "B"}}}),
           "A": "synthetic-shared", "B": "synthetic-shared"}
    with pytest.raises(scim.ScimError) as error:
        scim.authenticate("Bearer synthetic-shared", env)
    assert error.value.status == 401
    for config in ("bad", "[]", '{"tenants":{"org:a":{"token":"raw"}}}'):
        with pytest.raises(scim.ScimError):
            scim.authenticate("Bearer synthetic-shared", {**env, "SCIM_TRUST_CONFIG_JSON": config})


def test_real_auth_session_and_old_key_cannot_return_after_reactivation(setup, monkeypatch):
    from flask import session
    from services.auth_service import AuthService
    from werkzeug.security import check_password_hash

    client, store, _, _ = setup
    app = client.application

    class IsolatedAuth(AuthService):
        _users = {}
        _verified_keys = {}
        _api_key_prefix_index = {}

    def lookup(username):
        row = store.accounts.get(username)
        return IsolatedAuth._row_to_user(row) if row else None

    monkeypatch.setattr(IsolatedAuth, "_load_user_by_username", staticmethod(lookup))
    monkeypatch.setattr(IsolatedAuth, "_generate_api_key", staticmethod(lambda: "original-synthetic-key"))
    app.extensions["scim_service"].auth = IsolatedAuth
    app.add_url_rule("/who", endpoint="session_identity", view_func=lambda: {"authenticated": IsolatedAuth.get_current_user() is not None})
    created = user(client)
    assert created.status_code == 201
    original = copy.deepcopy(store.accounts["alice"])
    assert check_password_hash(original["api_key_hash"], "original-synthetic-key")
    with client.session_transaction() as signed:
        signed["authenticated"] = True
        signed["user"] = {"username": "alice", "api_key_prefix": original["api_key_prefix"]}
    assert client.get("/who").json["authenticated"]
    monkeypatch.setattr(IsolatedAuth, "_generate_api_key", staticmethod(lambda: "original-synthetic-rotated-key"))
    path = "Users/" + created.json["id"]
    assert call(client, "DELETE", path).status_code == 204
    assert store.accounts["alice"]["api_key_prefix"] != original["api_key_prefix"]
    assert client.get("/who").json["authenticated"] is False
    patch = {"schemas": [scim.PATCH_SCHEMA], "Operations": [{"op": "replace", "path": "active", "value": True}]}
    assert call(client, "PATCH", path, patch).status_code == 200
    assert not check_password_hash(store.accounts["alice"]["api_key_hash"], "original-synthetic-key")
    with app.test_request_context("/who"):
        session["authenticated"] = True
        session["user"] = {"username": "alice", "api_key_prefix": original["api_key_prefix"]}
        assert IsolatedAuth.get_current_user() is None


def test_transport_failure_has_no_retry_and_no_account_fallback(monkeypatch):
    for name in ("AUTH_STORAGE_BACKEND", "INTELLIGENCE_STORAGE_BACKEND"):
        monkeypatch.setenv(name, "d1")
    monkeypatch.setenv("CONFIG_REVISION_SYNC_ENABLED", "true")
    transport = Mock(side_effect=RuntimeError("private database details"))
    store = scim.D1ScimStore(transport)
    auth = Mock()
    service = scim.ScimService(store, auth)
    with pytest.raises(scim.ScimError) as error:
        service.create("org:a", "Users", {"userName": "alice"})
    assert error.value.status == 503
    assert "private database details" not in json.dumps(error.value.body())
    transport.assert_called_once_with({"version": 1, "operation": "probe"})
    auth._persist_user.assert_not_called()
    auth._generate_api_key.assert_not_called()
    transport.reset_mock()
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "sql")
    with pytest.raises(scim.ScimError) as error:
        store.probe()
    assert error.value.status == 503
    transport.assert_not_called()


def test_body_limit_unknown_metadata_and_partial_patch_do_not_mutate(setup):
    client, store, _, _ = setup
    created = user(client)
    path = "Users/" + created.json["id"]
    before = copy.deepcopy(store.rows)
    for operations in ([{"op": "replace", "path": "displayName", "value": "changed"},
                        {"op": "replace", "path": "roles", "value": ["admin"]}],
                       [{"op": "remove", "path": "members", "value": []}]):
        assert call(client, "PATCH", path, {"schemas": [scim.PATCH_SCHEMA], "Operations": operations}).status_code == 400
    assert store.rows == before
    assert user(client, meta={"unknown": "x"}).status_code == 400
    assert user(client, username=" alice ").status_code == 400
    raw = client.post("/scim/v2/Users", data="x" * (scim.MAX_BODY + 1),
                      headers={"Authorization": "Bearer synthetic-scim-a", "Content-Type": "application/scim+json"})
    assert raw.status_code == 413 and raw.json["status"] == "413"
    invalid = client.post("/scim/v2/Users", data="invalid", headers={
        "Authorization": "Bearer synthetic-scim-a", "Content-Type": "application/scim+json"})
    assert invalid.status_code == 400 and invalid.json["scimType"] == "invalidSyntax"
    for path in ("Users?sortBy=userName", "missing/nested/path"):
        result = call(client, "GET", path)
        assert result.status_code in {400, 404} and result.mimetype == "application/scim+json"
    assert call(client, "HEAD", "Users").status_code == 200


def test_successful_put_and_patch_all_mutable_attributes(setup):
    client, _, _, _ = setup
    created = user(client)
    path = "Users/" + created.json["id"]
    changed = call(client, "PUT", path, {"schemas": [scim.USER_SCHEMA], "userName": "alice", "externalId": "new-subject",
                                         "displayName": "Alice", "name": {"givenName": "Alice"}, "emails": []})
    assert changed.status_code == 200
    patch = {"schemas": [scim.PATCH_SCHEMA], "Operations": [
        {"op": "add", "path": "name", "value": {"familyName": "Example"}},
        {"op": "replace", "path": "externalId", "value": "final-subject"},
        {"op": "remove", "path": "displayName"},
        {"op": "remove", "path": "emails"}]}
    result = call(client, "PATCH", path, patch)
    assert result.status_code == 200 and result.json["name"] == {"givenName": "Alice", "familyName": "Example"}
    assert result.json["externalId"] == "final-subject"
    assert "emails" not in result.json and "displayName" not in result.json
    assert call(client, "PUT", path, {"userName": "bob"}).status_code == 400


def test_registration_default_keeps_existing_bytes_and_headers(monkeypatch):
    monkeypatch.setenv("SCIM_ENABLED", "")
    def baseline():
        app = Flask(__name__)
        app.add_url_rule("/raw", view_func=lambda: Response(b"opaque bytes", headers={"X-Raw": "identical"}))
        return app
    before = baseline().test_client().get("/raw")
    app = baseline()
    register_scim_routes(app)
    after = app.test_client().get("/raw")
    assert (before.data, before.status_code, list(before.headers)) == (after.data, after.status_code, list(after.headers))
