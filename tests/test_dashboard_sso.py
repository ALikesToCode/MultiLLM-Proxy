"""Cloudflare Access single sign-on, the audit log page and dashboard page hardening."""

import base64
import importlib
import json
import re
import sys
import time
from unittest.mock import patch

import pytest

from error_handlers import APIError
from services import audit_log, dashboard_sso
from services.intelligence_d1_store import PrivateIntelligenceError

TEAM = "https://acme.cloudflareaccess.com"
SECRET = "synthetic-access-proof-secret-0123456789"
OWNER_KEY = "synthetic-owner-admin-key"


def encode(claims):
    return base64.urlsafe_b64encode(json.dumps(claims).encode("utf-8")).rstrip(b"=").decode("ascii")


def asserted(claims, secret=SECRET):
    identity = encode(claims)
    return {dashboard_sso.IDENTITY_HEADER: identity, dashboard_sso.PROOF_HEADER: dashboard_sso.proof(secret.encode(), identity)}


def verified(email, method="GET", path="/login/access", **changes):
    now = int(time.time())
    return asserted({"v": 1, "status": "verified", "method": method, "path": path, "iat": now,
                     "email": email, "exp": now + 3600, "client": "203.0.113.7", **changes})


def refused(reason, method="GET"):
    return asserted({"v": 1, "status": "failed", "method": method, "path": "/login/access",
                     "iat": int(time.time()), "reason": reason, "client": "203.0.113.8"})


@pytest.fixture
def env(tmp_path, monkeypatch):
    values = {
        "ADMIN_USERNAME": "owner", "ADMIN_USERNAMES": "", "ADMIN_API_KEY": OWNER_KEY,
        "FLASK_SECRET_KEY": "synthetic-flask-secret", "JWT_SECRET": "synthetic-jwt-secret",
        "AUTH_STORAGE_BACKEND": "sql", "CONTROL_PLANE_DATABASE_URL": "",
        "AUTH_DB_PATH": str(tmp_path / "auth.sqlite3"), "RATE_LIMIT_DB_PATH": str(tmp_path / "limits.sqlite3"),
        "MODEL_REGISTRY_DB_PATH": str(tmp_path / "models.sqlite3"),
        "LOGIN_MAX_ATTEMPTS": "3", "LOGIN_ATTEMPT_WINDOW_SECONDS": "60", "LOGIN_LOCKOUT_SECONDS": "120",
        "CF_ACCESS_TEAM_DOMAIN": TEAM, "CF_ACCESS_PROOF_SECRET": SECRET, "DASHBOARD_SSO_ONLY": "",
        "CF_ACCESS_ALLOWED_EMAILS": "Alice@Example.com=alice, ops@example.com=bob, owner@example.com=owner, ghost@example.com=ghost",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return monkeypatch


@pytest.fixture
def events(monkeypatch):
    recorded = []
    monkeypatch.setattr(audit_log, "record", lambda action, outcome, **fields: recorded.append((action, outcome, fields)) or True)
    return recorded


@pytest.fixture
def app(env, events):
    for module_name in ("app", "route_helpers", "services.auth_service", "routes.core", "routes.dashboard_security"):
        sys.modules.pop(module_name, None)
    flask_app = importlib.import_module("app").create_app()
    flask_app.config["WTF_CSRF_ENABLED"] = False
    auth = sys.modules["services.auth_service"].AuthService
    with patch.object(auth, "get_current_user", return_value={"username": "owner", "is_admin": True}):
        auth.create_user("alice", scopes=["chat", "models"])
        # SQL storage accepts an administrator the admin allowlist does not name; SSO must not.
        auth.create_user("bob", is_admin=True)
    flask_app.auth = auth
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


def session_of(client):
    with client.session_transaction() as current:
        return dict(current)


def sign_in(client, email, **query):
    path = "/login/access" + (f"?next={query['next']}" if "next" in query else "")
    assert client.get(path, headers=verified(email)).status_code == 200
    return client.post(path, headers=verified(email, method="POST"), follow_redirects=False)


def test_proof_matches_the_worker_vector():
    # tests/test_access_sso_worker.mjs computes the same vector with WebCrypto.
    assert dashboard_sso.proof(SECRET.encode(), "eyJ2IjoxLCJzdGF0dXMiOiJ2ZXJpZmllZCJ9") == "oaPbB60bwqnp7F2jVzAydieQ_uEJovA6b8WqBnpa1Wo"


def test_assertions_need_a_valid_proof_bound_to_this_request(env):
    now = time.time()
    read = lambda headers, method="GET", path="/login/access", at=now: dashboard_sso.read_assertion(headers, method, path, at)
    good = read(verified("Alice@Example.com"))
    assert good == dashboard_sso.AccessAssertion(True, email="alice@example.com", expires_at=int(now) + 3600, client="203.0.113.7")
    headers = verified("alice@example.com")
    assert read(headers, method="POST") is None, "a GET assertion cannot be replayed as a POST"
    assert read(headers, path="/users") is None
    assert read(headers, at=now + 301) is None, "assertions are short-lived"
    assert read(verified("alice@example.com", exp=int(now) - 1)) is None
    assert read(asserted({**json.loads(base64.urlsafe_b64decode(headers[dashboard_sso.IDENTITY_HEADER] + "==")), "email": "owner@example.com"},
                         secret="another-secret-that-is-long-enough-000")) is None
    tampered = dict(headers)
    tampered[dashboard_sso.IDENTITY_HEADER] = encode({"v": 1, "status": "verified", "method": "GET", "path": "/login/access",
                                                      "iat": int(now), "email": "owner@example.com", "exp": int(now) + 60})
    assert read(tampered) is None
    assert read({}) is None
    assert read(refused("signature")) == dashboard_sso.AccessAssertion(False, reason="signature", client="203.0.113.8")
    env.setenv("CF_ACCESS_PROOF_SECRET", "too-short")
    assert read(verified("alice@example.com")) is None


def test_allowlist_maps_emails_to_accounts_and_denies_everything_else(env):
    env.setenv("CF_ACCESS_ALLOWED_EMAILS", " Alice@Example.com = alice ,carol@example.com, bad-entry, =x, dave@example.com=, eve@example.com=a\x01b")
    assert dashboard_sso.allowed_emails() == {"alice@example.com": "alice", "carol@example.com": "carol@example.com"}
    assert dashboard_sso.username_for_email("ALICE@example.com") == "alice"
    assert dashboard_sso.username_for_email("mallory@example.com") is None
    env.setenv("ADMIN_USERNAMES", "deputy, auditor ,")
    assert dashboard_sso.admin_usernames() == {"owner", "deputy", "auditor"}


def test_configuration_requires_an_access_team_domain_and_strong_secret(env):
    assert dashboard_sso.configured() and dashboard_sso.logout_url() == f"{TEAM}/cdn-cgi/access/logout"
    for name, value in (("CF_ACCESS_TEAM_DOMAIN", "https://attacker.example"), ("CF_ACCESS_TEAM_DOMAIN", "http://acme.cloudflareaccess.com"),
                        ("CF_ACCESS_PROOF_SECRET", "short")):
        with patch.dict("os.environ", {name: value}):
            assert not dashboard_sso.configured()
            assert dashboard_sso.logout_url() is None


def test_sso_confirms_then_starts_a_fresh_session(client, events):
    with client.session_transaction() as current:
        current.update({"csrf_token": "planted", "planted": "value", "user": {"username": "alice"}})
    page = client.get("/login/access?next=/users", headers=verified("alice@example.com"))
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert "Continue as alice" in html and "alice@example.com" in html
    assert 'action="/login/access?next=/users"' in html
    assert session_of(client).get("authenticated") is None, "GET never signs in"

    response = client.post("/login/access?next=/users", headers=verified("alice@example.com", method="POST"))
    assert (response.status_code, response.headers["Location"]) == (302, "/users")
    state = session_of(client)
    assert "planted" not in state and state.get("csrf_token") != "planted", "the old session is discarded"
    assert state["authenticated"] is True and state["auth_method"] == "access"
    assert state["user"]["username"] == "alice" and state["user"]["is_admin"] is False
    assert 0 < state["auth_expires_at"] - time.time() <= 3600
    assert events[-1] == ("sign_in", "succeeded", {"actor": "alice", "detail": "method=access email=alice@example.com"})
    assert client.get("/").status_code == 200


def test_unsafe_next_targets_are_ignored(client):
    response = sign_in(client, "alice@example.com", next="https://attacker.example/")
    assert response.headers["Location"] == "/"


def test_unknown_or_unverified_identities_are_refused_audited_and_throttled(client, events):
    for headers, message in (
        (verified("mallory@example.com"), "not allowed to sign in"),
        (verified("ghost@example.com"), "not allowed to sign in"),  # mapped, but no such account
        ({}, "did not carry a verified Cloudflare Access identity"),
        (refused("signature"), "could not verify this sign-in"),
        (verified("alice@example.com", method="POST"), "did not carry a verified"),  # a POST assertion on a GET
    ):
        response = client.get("/login/access", headers=headers)
        assert response.status_code == 403
        assert message in response.get_data(as_text=True)
        assert session_of(client).get("authenticated") is None
    assert [(action, outcome, fields["detail"]) for action, outcome, fields in events] == [
        ("sign_in", "refused", "method=access reason=email_not_allowed"),
        ("sign_in", "refused", "method=access reason=account_unavailable"),
        ("sign_in", "refused", "method=access reason=untrusted"),
        ("sign_in", "refused", "method=access reason=signature"),
        ("sign_in", "refused", "method=access reason=untrusted"),
    ]
    assert events[0][2]["actor"] == "mallory@example.com" and events[1][2]["target"] == "ghost"

    statuses = [client.get("/login/access", headers=verified("mallory@example.com")).status_code for _ in range(3)]
    assert statuses == [403, 429, 429], "the third failure for one identity locks it out"
    locked = client.get("/login/access", headers=verified("mallory@example.com"))
    assert int(locked.headers["Retry-After"]) >= 1
    assert sign_in(client, "alice@example.com").status_code == 302, "other identities are unaffected"


def test_sso_never_grants_admin_outside_the_admin_allowlist(client, env):
    sign_in(client, "ops@example.com")
    assert session_of(client)["user"]["is_admin"] is False
    assert "admin" not in session_of(client)["user"]["scopes"]
    assert client.get("/admin/audit").status_code == 403
    assert 'id="create-user-form"' not in client.get("/users").get_data(as_text=True)
    env.setenv("ADMIN_USERNAMES", "bob")
    assert client.get("/admin/audit").status_code == 200, "naming the username restores administration"
    env.setenv("ADMIN_USERNAMES", "")
    assert client.get("/admin/audit").status_code == 403

    owner = client.application.test_client()
    sign_in(owner, "owner@example.com")
    assert session_of(owner)["user"]["is_admin"] is True


def test_sso_sessions_end_with_the_access_token(client, env):
    sign_in(client, "alice@example.com")
    with client.session_transaction() as current:
        current["auth_expires_at"] = int(time.time()) - 1
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302 and response.headers["Location"].startswith("/login")
    assert session_of(client).get("authenticated") is None

    sign_in(client, "alice@example.com")
    env.setenv("CF_ACCESS_PROOF_SECRET", "")
    assert client.get("/", follow_redirects=False).status_code == 302, "disabling single sign-on ends its sessions"


def test_csrf_protects_the_sso_sign_in(app, client):
    app.config["WTF_CSRF_ENABLED"] = True
    response = client.post("/login/access", headers=verified("alice@example.com", method="POST"))
    assert response.status_code == 400
    assert session_of(client).get("authenticated") is None


def test_logout_is_audited_and_links_to_the_access_logout(client, events):
    sign_in(client, "alice@example.com")
    response = client.post("/logout")
    assert response.headers["Location"] == "/login?signed_out=access"
    assert events[-1] == ("sign_out", "succeeded", {"actor": "alice", "detail": "method=access"})
    assert session_of(client) == {}
    html = client.get("/login?signed_out=access").get_data(as_text=True)
    assert f'href="{TEAM}/cdn-cgi/access/logout"' in html


def test_password_sign_in_stays_available_and_is_audited(client, events):
    html = client.get("/login").get_data(as_text=True)
    assert 'href="/login/access"' in html and 'name="api_key"' in html
    response = client.post("/login", data={"username": "owner", "api_key": OWNER_KEY})
    assert response.status_code == 302
    assert events[-1] == ("sign_in", "succeeded", {"actor": "owner", "detail": "method=password"})
    client.post("/logout")
    assert events[-1] == ("sign_out", "succeeded", {"actor": "owner", "detail": "method=password"})


def test_sso_only_disables_password_sign_in_but_not_api_keys(client, env):
    client.post("/login", data={"username": "owner", "api_key": OWNER_KEY})
    assert client.get("/", follow_redirects=False).status_code == 200
    env.setenv("DASHBOARD_SSO_ONLY", "true")
    assert client.get("/", follow_redirects=False).status_code == 302, "existing password sessions end"
    html = client.get("/login").get_data(as_text=True)
    assert 'name="api_key"' not in html and "Continue with Cloudflare Access" in html
    response = client.post("/login", data={"username": "owner", "api_key": OWNER_KEY})
    assert response.status_code == 403 and session_of(client).get("authenticated") is None
    assert client.get("/v1/models", headers={"Authorization": f"Bearer {OWNER_KEY}"}).status_code != 401
    sign_in(client, "owner@example.com")
    assert client.get("/", follow_redirects=False).status_code == 200


def test_sso_route_is_absent_until_configured(client, env):
    env.setenv("CF_ACCESS_PROOF_SECRET", "")
    assert client.get("/login/access", headers=verified("alice@example.com")).status_code == 404
    assert 'href="/login/access"' not in client.get("/login").get_data(as_text=True)


class FakeAuditDomain:
    def __init__(self, response=None, error=None):
        self.calls, self.response, self.error = [], response, error

    def __call__(self, payload, *, endpoint):
        assert endpoint == "users"
        self.calls.append(payload)
        if self.error:
            raise self.error
        return self.response


def entry(**changes):
    return {"source": "event", "id": 7, "at": "2026-09-26T12:00:00.000Z", "actor": "owner", "action": "sign_in",
            "outcome": "succeeded", "target": None, "detail": "method=access email=owner@example.com",
            "is_admin": None, "scopes": None, "api_key_prefix": None, "revoked_at": None, **changes}


def admin(client):
    client.post("/login", data={"username": "owner", "api_key": OWNER_KEY})


def test_audit_page_is_admin_only(client):
    assert client.get("/admin/audit", follow_redirects=False).headers["Location"].startswith("/login")
    sign_in(client, "alice@example.com")
    assert client.get("/admin/audit").status_code == 403
    assert client.get("/admin/audit", headers={"Accept": "application/json"}).status_code == 403


def test_audit_page_filters_and_pages_through_the_private_handler(client, monkeypatch):
    domain = FakeAuditDomain({"version": 1, "entries": [
        entry(), entry(source="account", id=12, actor=None, action="upsert", outcome="refused", target="mallory", detail=None,
                       is_admin=1, scopes="admin,chat", api_key_prefix="mllm_abcdefgh"),
    ], "next": {"account": 12, "event": 0}})
    monkeypatch.setattr(audit_log, "request_private_intelligence", domain)
    monkeypatch.setattr(audit_log, "available", lambda: True)
    admin(client)
    response = client.get("/admin/audit?actor=owner&action=sign_in&before=40:&limit=20")
    assert response.status_code == 200
    assert domain.calls[-1] == {"operation": "audit_list", "actor": "owner", "target": None, "action": "sign_in",
                                "before_account": 40, "before_event": None, "limit": 20}
    html = response.get_data(as_text=True)
    assert "method=access email=owner@example.com" in html and "mallory" in html and "mllm_abcdefgh" in html
    older = re.search(r'href="([^"]+)" rel="next"', html).group(1).replace("&amp;", "&")
    assert "before=12:0" in older and "actor=owner" in older and "action=sign_in" in older and "limit=20" in older
    payload = client.get("/admin/audit", headers={"Accept": "application/json"}).get_json()
    assert payload["next"] == "12:0" and payload["entries"][1]["target"] == "mallory"
    assert domain.calls[-1]["before_account"] is None and domain.calls[-1]["limit"] == 50

    for query in ("action=drop", "before=x", "before=:", "limit=101", "limit=0", "actor=" + "a" * 300):
        assert client.get(f"/admin/audit?{query}", headers={"Accept": "application/json"}).status_code == 400, query


def test_audit_page_rejects_malformed_storage_answers(client, monkeypatch):
    monkeypatch.setattr(audit_log, "available", lambda: True)
    monkeypatch.setattr(audit_log, "READ_RETRY_DELAY_SECONDS", 0)
    admin(client)
    for response in ({"version": 1, "entries": [entry(extra=1)], "next": None},
                     {"version": 1, "entries": [entry()] * 51, "next": None},
                     {"version": 1, "entries": [], "next": {"account": -1, "event": None}},
                     {"version": 1, "entries": [entry(is_admin=True)], "next": None}):
        monkeypatch.setattr(audit_log, "request_private_intelligence", FakeAuditDomain(response))
        assert client.get("/admin/audit", headers={"Accept": "application/json"}).status_code == 503
    failing = FakeAuditDomain(error=PrivateIntelligenceError(503, "storage_unavailable"))
    monkeypatch.setattr(audit_log, "request_private_intelligence", failing)
    assert client.get("/admin/audit").status_code == 503
    assert len(failing.calls) == 2, "a transient failure is retried once"


def test_audit_page_explains_when_accounts_are_not_in_d1(client):
    admin(client)
    html = client.get("/admin/audit").get_data(as_text=True)
    assert "AUTH_STORAGE_BACKEND=d1" in html
    assert 'href="/admin/audit"' in client.get("/users").get_data(as_text=True)


def test_administrator_setting_changes_are_audited(client, events):
    admin(client)
    assert client.post("/users/alice/rotate-key").status_code == 200
    assert client.post("/users", json={"username": "carol"}).status_code == 200
    assert events[-2:] == [
        ("setting_change", "succeeded", {"actor": "owner", "target": "alice", "detail": "setting=account.rotate_key status=200"}),
        ("setting_change", "succeeded", {"actor": "owner", "target": "carol", "detail": "setting=account.create status=200"}),
    ]
    operator = client.application.test_client()
    sign_in(operator, "alice@example.com")
    assert operator.delete("/users/carol").status_code == 403
    assert events[-1] == ("setting_change", "refused", {"actor": "alice", "target": "carol", "detail": "setting=account.delete status=403"})
    count = len(events)
    client.get("/users")
    client.post("/users/nobody/rotate-key")
    assert len(events) == count, "reads and invalid requests are not setting changes"


def test_record_is_bounded_best_effort_and_needs_d1(monkeypatch):
    domain = FakeAuditDomain({"version": 1, "recorded": True})
    monkeypatch.setattr(audit_log, "request_private_intelligence", domain)
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "sql")
    assert audit_log.record("sign_out", "succeeded", actor="owner") is False and domain.calls == []
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "d1")
    assert audit_log.record("sign_in", "refused", actor="evil\nactor", target="t" * 300, detail="d" * 600) is True
    assert domain.calls[-1] == {"operation": "audit_record", "action": "sign_in", "outcome": "refused",
                                "actor": "evil actor", "target": "t" * 256, "detail": "d" * 512}
    domain.error = PrivateIntelligenceError(503, "storage_unavailable")
    assert audit_log.record("sign_out", "succeeded", actor="owner") is False
    with pytest.raises(ValueError):
        audit_log.record("delete_history", "succeeded")
    with pytest.raises(APIError):
        audit_log.parse_query({"action": "upsert", "before": "1:2:3"})


def test_dashboard_pages_carry_a_strict_content_security_policy(client):
    page = client.get("/login", base_url="https://gateway.example")
    policy = page.headers["Content-Security-Policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'",
                      "frame-ancestors 'none'", "form-action 'self'"):
        assert directive in policy
    assert "unsafe-inline" not in policy
    assert page.headers["Permissions-Policy"].startswith("camera=()")
    assert page.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert page.headers["X-Frame-Options"] == "DENY"
    asset = client.get("/static/offline.html")
    assert "script-src" not in asset.headers["Content-Security-Policy"], "static files keep the baseline policy"
    api = client.get("/health")
    assert "script-src" not in api.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" not in client.get("/login").headers, "plain HTTP never sets HSTS"


def test_session_cookie_flags(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] is True
