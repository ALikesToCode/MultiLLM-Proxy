"""Broker assertions are verified before durable identity or session work."""
import base64
import importlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from flask import Flask, Response, session
from flask_wtf.csrf import CSRFProtect, generate_csrf

from services import saml_federation as saml
from services.enterprise_contract import TenantContext
from routes.saml_federation import SAML_PUBLIC_ENDPOINTS, register_saml_federation_routes

NOW = 1_800_000_000
CALLBACK = "https://gateway.example/auth/saml/callback"
ISSUER = "https://broker.example/issuer"
AUDIENCE = "gateway.example"


class Store:
    def __init__(self):
        self.requests, self.links, self.audit, self.calls = {}, {}, [], []
        self.lock = threading.Lock()
        self.available = True

    def __call__(self, body):
        with self.lock:
            self.calls.append(body)
            if not self.available:
                raise RuntimeError("private storage detail")
            op = body["operation"]
            if op == "ready":
                return {"version": 1, "ready": True}
            if op == "create_request":
                self.requests[body["state_digest"]] = {**body, "claimed_at": None}
                return {"version": 1, "created": True}
            if op == "claim_request":
                row = self.requests.get(body["state_digest"])
                ok = row and row["nonce_digest"] == body["nonce_digest"] and row["recipient_digest"] == body["recipient_digest"] and row["expires_at"] > body["now"] and row["claimed_at"] is None
                if ok:
                    row["claimed_at"] = body["now"]
                return {"version": 1, "claimed": bool(ok)}
            if op == "lookup_link":
                link = next((row for row in self.links.values() if row["issuer_digest"] == body["issuer_digest"] and row["subject_digest"] == body["subject_digest"] and row["active"]), None)
                return {"version": 1, "link": link}
            if op == "list_links":
                return {"version": 1, "links": list(self.links.values())}
            if op == "get_link":
                return {"version": 1, "link": self.links.get(body["id"])}
            if op == "put_link":
                self.links[body["link"]["id"]] = {**body["link"], "active": 1}
                self.audit.append(body)
                return {"version": 1, "link": self.links[body["link"]["id"]]}
            if op == "deactivate_link":
                link = self.links.get(body["id"])
                if link:
                    link["active"] = 0
                self.audit.append(body)
                return {"version": 1, "deactivated": bool(link)}
            if op == "audit":
                self.audit.append(body)
                return {"version": 1, "recorded": True}
            raise AssertionError(op)


@pytest.fixture(params=["EdDSA", "RS256"])
def signer(request):
    key = ed25519.Ed25519PrivateKey.generate() if request.param == "EdDSA" else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return request.param, key, pem


def settings(signer, **changes):
    alg, _, pem = signer
    return {"SAML_ENABLED": "true", "SAML_BROKER_URL": "https://broker.example/login?realm=enterprise", "SAML_CALLBACK_URL": CALLBACK,
            "SAML_TRUST_CONFIG_JSON": json.dumps({"issuer": ISSUER, "audience": AUDIENCE, "keys": [{"kid": "pinned", "alg": alg, "public_key_pem": pem}], "max_age_seconds": 300}), **changes}


def signed(signer, claims, **header_changes):
    alg, key, _ = signer
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=")
    data = encode({"alg": alg, "kid": "pinned", "typ": "JWT", **header_changes}) + b"." + encode(claims)
    signature = key.sign(data) if alg == "EdDSA" else key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return (data + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()


@pytest.fixture
def registered(monkeypatch, signer):
    env = settings(signer)
    for key in ("SAML_ENABLED", "SAML_BROKER_URL", "SAML_CALLBACK_URL", "SAML_TRUST_CONFIG_JSON"):
        monkeypatch.setenv(key, env[key])
    app = Flask(__name__)
    app.config.update(SECRET_KEY="synthetic-saml-session", TESTING=True, WTF_CSRF_ENABLED=False)
    csrf = CSRFProtect(app)
    store, issue = Store(), Mock(return_value=True)
    accounts = {"alice": {"username": "alice", "is_admin": False, "scopes": ["chat"], "revoked_at": None, "expires_at": None}}
    service = saml.SamlFederation(saml.load_config(env), saml.SamlStore(store), session_issuer=issue, account_lookup=accounts.get, clock=lambda: NOW)
    app.extensions["saml_federation"] = service
    register_saml_federation_routes(app, csrf)
    route_globals = register_saml_federation_routes.__globals__
    monkeypatch.setitem(route_globals, "admin_dashboard_user", lambda: {"username": "operator", "is_admin": True})
    app.add_url_rule("/csrf-fixture", view_func=lambda: {"token": generate_csrf()})
    return app, app.test_client(), service, store, issue, accounts, route_globals


def start(client):
    response = client.get("/auth/saml/login?next=https://attacker.example")
    assert response.status_code == 302
    url = urlsplit(response.location)
    assert (url.scheme, url.netloc, url.path) == ("https", "broker.example", "/login")
    query = parse_qs(url.query)
    assert "next" not in query
    return {"iss": ISSUER, "aud": AUDIENCE, "sub": "external:alice", "iat": NOW, "exp": NOW + 300,
            "nonce": query["nonce"][0], "state": query["state"][0], "recipient": CALLBACK, "is_admin": True, "org_id": "foreign"}


def link(service, **changes):
    return service.put_link({"issuer": ISSUER, "subject": "external:alice", "account": "alice", "org_id": "org:one", "team_id": "team:one", "grants_revision": 2, **changes}, "operator")


def callback(client, signer, claims, method="GET", **headers):
    values = {"token": signed(signer, claims, **headers), "state": claims["state"]}
    return client.get("/auth/saml/callback", query_string=values) if method == "GET" else client.post("/auth/saml/callback", data=values)


@pytest.mark.parametrize("flag", ["", "false", "0", "malformed"])
def test_disabled_routes_before_auth_csrf_and_storage(registered, flag):
    app, client, service, store, _, _, _ = registered
    service.config = saml.load_config({"SAML_ENABLED": flag})
    app.config["WTF_CSRF_ENABLED"] = True
    for path in ("login", "callback", "acs", "metadata", "unknown"):
        for method in ("GET", "POST"):
            assert client.open("/auth/saml/" + path, method=method).status_code == 404
    assert client.put("/admin/saml/links", json={}).status_code == 404
    assert store.calls == []


def test_existing_response_is_unchanged(monkeypatch):
    monkeypatch.setenv("SAML_ENABLED", "")
    def baseline():
        app = Flask(__name__)
        app.add_url_rule("/raw", view_func=lambda: Response(b"unchanged bytes", headers={"X-Existing": "same"}))
        return app
    before = baseline().test_client().get("/raw")
    app = baseline()
    register_saml_federation_routes(app, CSRFProtect())
    after = app.test_client().get("/raw")
    assert (before.data, list(before.headers)) == (after.data, list(after.headers))


@pytest.mark.parametrize("change", [{"SAML_BROKER_URL": "http://broker.example"}, {"SAML_BROKER_URL": "https://user:pass@broker.example"}, {"SAML_BROKER_URL": "https://broker.example/#fragment"}, {"SAML_BROKER_URL": "https://broker.example?nonce=bad"}, {"SAML_CALLBACK_URL": ""}, {"SAML_TRUST_CONFIG_JSON": "{}"}, {"SAML_TRUST_CONFIG_JSON": "private-invalid"}])
def test_config_invalid_is_off_and_logs_once_without_values(signer, change, caplog):
    saml._warn_once.cache_clear()
    for _ in range(2):
        assert not saml.load_config(settings(signer, **change)).enabled
    assert len(caplog.records) == 1
    assert "private-invalid" not in caplog.text and "user:pass" not in caplog.text


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_valid_assertion_uses_only_existing_account_and_bound_authority(registered, signer, method):
    _, client, service, store, issue, _, _ = registered
    link(service)
    claims = start(client)
    authority = Mock(side_effect=lambda assertion, operation: operation.context)
    service.identity_authority = authority
    response = callback(client, signer, claims, method)
    assert response.status_code == 302 and response.location == "/"
    issue.assert_called_once_with("alice", TenantContext("alice", "org:one", "team:one", 2))
    assertion, operation = authority.call_args.args
    assert assertion.verified and operation.context.org_id == "org:one"
    assert response.headers["Cache-Control"] == "no-store"
    content = json.dumps(store.requests) + json.dumps(store.audit)
    assert claims["nonce"] not in content and claims["state"] not in content and "external:alice" not in content
    assert callback(client, signer, claims).json["error"]["code"] == "saml_assertion_replayed"
    assert issue.call_count == 1


@pytest.mark.parametrize("change", [{"iss": "other"}, {"aud": "other"}, {"aud": [AUDIENCE, "other"]}, {"nonce": "wrong"}, {"recipient": "https://attacker.example"}, {"exp": NOW - 10}, {"iat": NOW + 20}, {"exp": NOW + 301}, {"iat": True}, {"exp": 1.2}, {"sub": ""}])
def test_invalid_claims_never_issue_session(registered, signer, change):
    _, client, service, _, issue, _, _ = registered
    link(service)
    response = callback(client, signer, {**start(client), **change})
    assert response.status_code == 400
    issue.assert_not_called()


@pytest.mark.parametrize("headers", [{"kid": "unknown"}, {"alg": "none"}, {"alg": "HS256"}, {"alg": "RS512"}, {"crit": ["private"]}, {"jku": "https://attacker.example"}])
def test_untrusted_headers_are_rejected(registered, signer, headers):
    _, client, service, _, issue, _, _ = registered
    link(service)
    assert callback(client, signer, start(client), **headers).status_code == 400
    issue.assert_not_called()


def test_signature_and_browser_binding_are_required(registered, signer):
    app, client, service, store, issue, _, _ = registered
    link(service)
    claims = start(client)
    token = signed(signer, claims)
    head, body, sig = token.split(".")
    assert client.get("/auth/saml/callback", query_string={"token": head + "." + body + "." + ("A" if sig[0] != "A" else "B") + sig[1:], "state": claims["state"]}).status_code == 400
    assert app.test_client().get("/auth/saml/callback", query_string={"token": token, "state": claims["state"]}).status_code == 400
    assert all(row["claimed_at"] is None for row in store.requests.values())
    issue.assert_not_called()


def test_unlinked_inactive_and_foreign_authority_cannot_grant(registered, signer):
    _, client, service, store, issue, _, _ = registered
    assert callback(client, signer, start(client)).json["error"]["code"] == "saml_subject_unlinked"
    saved = link(service)
    service.deactivate_link(saved["link"]["id"], "operator")
    assert callback(client, signer, start(client)).status_code == 403
    link(service)
    service.identity_authority = lambda *_: TenantContext("alice", "foreign")
    assert callback(client, signer, start(client)).status_code == 403
    issue.assert_not_called()
    assert store.links


def test_missing_storage_and_session_fail_closed(registered, signer):
    _, client, service, store, issue, _, _ = registered
    link(service)
    claims = start(client)
    store.available = False
    for response in (client.get("/auth/saml/login"), callback(client, signer, claims), client.get("/admin/saml/links")):
        assert response.status_code == 503 and response.json["error"]["code"] == "saml_storage_unavailable"
        assert b"private storage" not in response.data
    issue.assert_not_called()
    store.available = True
    service.session_issuer = saml.issue_dashboard_session
    response = callback(client, signer, claims)
    assert response.status_code == 503 and response.json["error"]["code"] == "saml_session_unavailable"


def test_revoked_or_missing_account_has_no_session(registered, signer):
    _, client, service, _, issue, accounts, _ = registered
    link(service)
    accounts["alice"]["revoked_at"] = "2026-01-01"
    assert callback(client, signer, start(client)).status_code == 403
    accounts.clear()
    assert callback(client, signer, start(client)).status_code == 403
    issue.assert_not_called()


def test_admin_links_require_session_and_csrf_and_keep_history(registered):
    app, client, _, store, _, _, route_module = registered
    app.config["WTF_CSRF_ENABLED"] = True
    payload = {"issuer": ISSUER, "subject": "external:alice", "account": "alice"}
    assert client.put("/admin/saml/links", json=payload).status_code == 400
    token = client.get("/csrf-fixture").json["token"]
    response = client.put("/admin/saml/links", json=payload, headers={"X-CSRFToken": token})
    assert response.status_code == 200
    identifier = response.json["link"]["id"]
    assert client.delete("/admin/saml/links/" + identifier, headers={"X-CSRFToken": token}).json["deactivated"]
    assert store.links[identifier]["active"] == 0
    route_module["admin_dashboard_user"] = Mock(side_effect=saml.SamlError("admin_required", 403))
    assert client.get("/admin/saml/links").status_code == 403
    assert len(store.audit) == 2


def test_native_endpoints_never_claim_readiness(registered):
    _, client, _, _, issue, _, _ = registered
    for path in ("acs", "metadata"):
        response = client.get("/auth/saml/" + path)
        assert response.status_code == 503 and response.json["error"]["code"] == "saml_native_unavailable"
    issue.assert_not_called()


def test_atomic_replay_claim(registered, signer):
    _, client, service, _, issue, _, _ = registered
    link(service)
    claims = start(client)
    def consume(_):
        try:
            service.complete(signed(signer, claims), claims["state"], saml.digest(claims["state"]))
            return 200
        except saml.SamlError as error:
            return error.status
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(consume, range(2))) == [200, 400]
    assert issue.call_count == 1


def test_session_issuer_failure_restores_browser_session(registered, signer):
    _, client, service, _, _, _, _ = registered
    link(service)
    claims = start(client)
    def partial_issue(*_):
        session.clear()
        session["authenticated"] = True
        raise RuntimeError("private session detail")
    service.session_issuer = partial_issue
    response = callback(client, signer, claims)
    assert response.status_code == 503 and response.json["error"]["code"] == "saml_session_unavailable"
    with client.session_transaction() as saved:
        assert "authenticated" not in saved and saved["saml_state_digest"] == saml.digest(claims["state"])
    assert b"private session detail" not in response.data


def test_audit_failure_prevents_session_issue(registered, signer):
    _, client, service, store, issue, _, _ = registered
    link(service)
    original_call = store.__call__
    def failed_audit(body):
        if body["operation"] == "audit":
            raise RuntimeError("audit unavailable")
        return original_call(body)
    service.store = saml.SamlStore(failed_audit)
    assert callback(client, signer, start(client)).json["error"]["code"] == "saml_storage_unavailable"
    issue.assert_not_called()


def test_expired_request_cannot_use_fresh_token(registered, signer):
    _, client, service, _, issue, _, _ = registered
    link(service)
    claims = start(client)
    service.clock = lambda: NOW + 301
    claims.update(iat=NOW + 301, exp=NOW + 601)
    response = callback(client, signer, claims)
    assert response.json["error"]["code"] == "saml_assertion_replayed"
    issue.assert_not_called()


def test_pinned_algorithm_mismatch_and_strict_trust_bounds(signer):
    config = settings(signer)
    trust = json.loads(config["SAML_TRUST_CONFIG_JSON"])
    for age in (0, 301, True, "300"):
        assert not saml.load_config({**config, "SAML_TRUST_CONFIG_JSON": json.dumps({**trust, "max_age_seconds": age})}).enabled
    for change in ({"alg": "HS256"}, {"alg": "none"}, {"alg": "RS256" if signer[0] == "EdDSA" else "EdDSA"}):
        assert not saml.load_config({**config, "SAML_TRUST_CONFIG_JSON": json.dumps({**trust, "keys": [{**trust["keys"][0], **change}]})}).enabled
    assert not saml.load_config({**config, "SAML_TRUST_CONFIG_JSON": json.dumps({**trust, "keys": trust["keys"] * 2})}).enabled


def test_request_binding_and_envelopes_cannot_be_spoofed(registered, signer):
    _, client, service, _, issue, _, _ = registered
    link(service)
    claims = start(client)
    token = signed(signer, claims)
    assert client.get("/auth/saml/callback", query_string={"token": token, "state": "spoofed"}).status_code == 400
    assert client.post("/auth/saml/callback", json={"token": token, "state": claims["state"]}).status_code == 400
    assert client.get("/auth/saml/callback", query_string=[("token", token), ("token", token), ("state", claims["state"])]).status_code == 400
    assert client.get("/auth/saml/callback", query_string={"token": "x" * 17000, "state": claims["state"]}).status_code == 400
    issue.assert_not_called()


def test_admin_guard_requires_real_dashboard_administrator(monkeypatch):
    routes = importlib.import_module(register_saml_federation_routes.__module__)
    auth = importlib.import_module("services.auth_service").AuthService
    monkeypatch.setattr(auth, "is_authenticated", lambda: False)
    with pytest.raises(saml.SamlError) as failed:
        routes.admin_dashboard_user()
    assert failed.value.status == 401
    monkeypatch.setattr(auth, "is_authenticated", lambda: True)
    monkeypatch.setattr(auth, "get_current_user", lambda: {"username": "alice", "is_admin": False})
    with pytest.raises(saml.SamlError) as failed:
        routes.admin_dashboard_user()
    assert failed.value.status == 403


def test_application_callback_with_public_endpoint_registration(monkeypatch, tmp_path, signer):
    env = {**settings(signer), "FLASK_SECRET_KEY": "synthetic-saml-session", "JWT_SECRET": "synthetic-saml-jwt",
           "ADMIN_API_KEY": "synthetic-saml-admin", "AUTH_DB_PATH": str(tmp_path / "auth.sqlite3"),
           "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3"), "RATE_LIMIT_DB_PATH": str(tmp_path / "limits.sqlite3"),
           "INTELLIGENCE_STORAGE_BACKEND": "", "CF_ACCESS_TEAM_DOMAIN": "", "CF_ACCESS_SSO_ONLY": "false"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with patch("config.load_runtime_env"), patch("env_loader.load_runtime_env"), patch("services.usage_ledger.start"), \
            patch("requests.Session.send", side_effect=AssertionError("No network")):
        module = importlib.import_module("app")
        with patch.object(module, "load_runtime_env"):
            app = module.create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        accounts = {"alice": {"username": "alice", "is_admin": False, "scopes": ["chat"], "api_key_prefix": "synthetic"}}
        store = Store()
        def issue(account, context):
            assert context == TenantContext("alice")
            session.clear()
            session["authenticated"] = True
            session["user"] = {"username": account, "is_admin": accounts[account]["is_admin"], "scopes": accounts[account]["scopes"],
                               "api_key_prefix": "synthetic", "session_id": "synthetic-session"}
            return True
        service = saml.SamlFederation(saml.load_config(env), saml.SamlStore(store), session_issuer=issue, account_lookup=accounts.get, clock=lambda: NOW)
        app.extensions["saml_federation"] = service
        register_saml_federation_routes(app, app.extensions["csrf"])
        link(service, org_id=None, team_id=None, grants_revision=0)
        client = app.test_client()
        # Exercise the existing guard first, then the required static allowlist integration.
        blocked = client.get("/auth/saml/login")
        assert blocked.status_code == 302 and urlsplit(blocked.location).path == "/login"
        guard = next(hook for hook in app.before_request_funcs[None] if hook.__name__ == "handle_redirects")
        monkeypatch.setitem(guard.__globals__, "PRODUCT_PUBLIC_ENDPOINTS", guard.__globals__["PRODUCT_PUBLIC_ENDPOINTS"] | SAML_PUBLIC_ENDPOINTS)
        headers = next(hook for hook in app.after_request_funcs[None] if hook.__name__ == "add_response_headers")
        for auth in {guard.__globals__["AuthService"], headers.__globals__["AuthService"]}:
            monkeypatch.setattr(auth, "_load_user_by_username", accounts.get)
        claims = start(client)
        response = callback(client, signer, claims, "POST")
        assert response.status_code == 302
        with client.session_transaction() as saved:
            assert saved["authenticated"] is True and saved["user"]["is_admin"] is False
            assert saved["user"]["scopes"] == ["chat"]
        assert callback(client, signer, claims).json["error"]["code"] == "saml_assertion_replayed"
