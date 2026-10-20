"""Revision polling never certifies configuration that was not loaded."""
import threading
import time
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from flask import Flask

from services.config_revision_sync import RevisionSync, SyncSettings, load_settings
from services.gateway_extensions import register_gateway_extensions


def harness(*, security=False):
    now = [100.0]
    revisions = {"models": 0}
    loads = []
    def fetch(domains):
        return {name: revisions[name] for name in domains}
    sync = RevisionSync(SyncSettings(True, 30, 5), fetch=fetch,
                        clock=lambda: now[0], jitter=lambda: 0.5)
    sync.register("models", lambda revision: loads.append(revision), security=security)
    return sync, now, revisions, loads


@pytest.mark.parametrize("env", [{}, {"CONFIG_REVISION_SYNC_ENABLED": ""},
    {"CONFIG_REVISION_SYNC_ENABLED": "invalid"},
    {"CONFIG_REVISION_SYNC_ENABLED": "true", "CONFIG_SYNC_TTL_SECONDS": "nan"},
    {"CONFIG_REVISION_SYNC_ENABLED": "true", "CONFIG_SECURITY_TTL_SECONDS": "0"},
    {"CONFIG_REVISION_SYNC_ENABLED": "true", "CONFIG_SECURITY_TTL_SECONDS": "6"}])
def test_disabled_or_malformed_settings_are_inert(env):
    settings = load_settings(env)
    assert not settings.enabled
    fetch = Mock(side_effect=AssertionError("No storage"))
    sync = RevisionSync(settings, fetch=fetch)
    sync.register("models", Mock(), security=True)
    sync.tick()
    assert sync.security_ready()
    fetch.assert_not_called()


def test_empty_ttls_use_defaults():
    assert load_settings({"CONFIG_REVISION_SYNC_ENABLED": "true",
                          "CONFIG_SYNC_TTL_SECONDS": "", "CONFIG_SECURITY_TTL_SECONDS": ""}) == SyncSettings(True, 30, 5)


def test_two_instances_only_reload_newer_committed_revision():
    first, now, revisions, loads = harness()
    second_loads = []
    second = RevisionSync(first.settings, fetch=first.fetch, clock=lambda: now[0], jitter=lambda: 0)
    second.register("models", second_loads.append)
    first.tick(); second.tick()
    assert loads == second_loads == [0]
    now[0] += 31
    first.tick(); second.tick()
    assert loads == second_loads == [0]
    revisions["models"] = 2
    now[0] += 31
    first.tick(); second.tick()
    assert loads == second_loads == [0, 2]
    assert first.status()["domains"]["models"]["revision"] == 2


def test_outage_marks_ordinary_stale_and_security_fails_closed():
    ordinary, now, _, _ = harness()
    security, security_now, _, _ = harness(security=True)
    assert not security.security_ready()
    ordinary.tick(); security.tick()
    assert security.security_ready()
    ordinary.fetch = security.fetch = Mock(side_effect=RuntimeError("private detail"))
    now[0] += 31; security_now[0] += 5.01
    ordinary.tick(); security.tick()
    assert ordinary.status()["domains"]["models"]["stale"]
    assert not security.security_ready()
    assert "private detail" not in str(security.status())


def test_failed_reload_and_revision_rollback_do_not_renew_security():
    sync, now, revisions, _ = harness(security=True)
    sync.tick()
    revisions["models"] = 1
    sync.register("models", Mock(side_effect=RuntimeError("offline")), security=True)
    now[0] += 5
    sync.tick()
    assert not sync.security_ready()
    assert sync.status()["domains"]["models"]["revision"] is None
    sync.register("models", lambda revision: None, security=True)
    sync.tick()
    now[0] += 5
    sync.tick()
    assert sync.security_ready()
    revisions["models"] = 0
    now[0] += 5
    sync.tick()
    assert not sync.security_ready()
    assert sync.status()["domains"]["models"]["revision"] == 1


def test_write_during_reload_never_certifies_mixed_revision():
    sync, now, revisions, _ = harness(security=True)
    sync.register("models", lambda revision: revisions.update(models=revision + 1), security=True)
    sync.tick()
    assert not sync.security_ready()


def test_inflight_poll_and_failures_cannot_create_refresh_storm():
    sync, now, _, _ = harness(security=True)
    entered, release = threading.Event(), threading.Event()
    def fetch(domains):
        entered.set()
        assert release.wait(2)
        return {name: 0 for name in domains}
    sync.fetch = Mock(side_effect=fetch)
    thread = threading.Thread(target=sync.tick)
    thread.start()
    assert entered.wait(2)
    for _ in range(100):
        sync.tick()
    release.set(); thread.join(2)
    assert not thread.is_alive()
    assert sync.fetch.call_count == 2  # read, load, verification read
    sync.fetch = Mock(side_effect=RuntimeError("offline"))
    now[0] += 5
    for _ in range(100):
        sync.tick()
    assert sync.fetch.call_count == 1


@pytest.mark.parametrize("jitter", [0, 1])
def test_jitter_poll_bound_never_exceeds_security_ttl(jitter):
    sync, now, _, _ = harness(security=True)
    sync.jitter = lambda: jitter
    sync.tick()
    due = sync.status()["domains"]["models"]["next_poll_seconds"]
    assert 4 <= due <= 5


def test_static_registrar_preserves_order_and_disabled_requests():
    app = Flask(__name__)
    app.config["TESTING"] = True
    calls = []
    with patch("services.gateway_extensions.load_settings", return_value=SyncSettings()):
        register_gateway_extensions(app, callbacks=(lambda app: calls.append("retention"),
                                                     lambda app: calls.append("admission")))
    @app.get("/v1/probe")
    def probe():
        return "unchanged", 200, {"X-Existing": "yes"}
    response = app.test_client().get("/v1/probe")
    assert response.data == b"unchanged"
    assert response.headers["X-Existing"] == "yes"
    assert calls == ["retention", "admission"]
    assert app.test_client().get("/admin/config/revisions").status_code == 404


def test_registered_security_guard_and_admin_freshness():
    app = Flask(__name__)
    app.config["TESTING"] = True
    sync, now, _, _ = harness(security=True)
    register_gateway_extensions(app, revision_sync=sync)
    @app.post("/v1/chat/completions")
    def dispatch():
        return {"dispatched": True}
    client = app.test_client()
    assert client.post("/v1/chat/completions").status_code == 503
    sync.tick()
    assert client.post("/v1/chat/completions").status_code == 200
    now[0] += 5.01
    assert client.post("/v1/chat/completions").status_code == 503
    with patch("route_helpers.AuthService.is_authenticated", return_value=True), \
            patch("services.gateway_extensions.AuthService.get_current_user", return_value={"is_admin": True}):
        result = client.get("/admin/config/revisions")
        assert result.status_code == 200
        assert result.json["domains"]["models"]["stale"]
    with patch("route_helpers.AuthService.is_authenticated", return_value=True), \
            patch("services.gateway_extensions.AuthService.get_current_user", return_value={"is_admin": False}):
        assert client.get("/admin/config/revisions").status_code == 403


def test_owned_route_reader_uses_revision_cache_only_when_enabled(monkeypatch):
    from services import auto_route_d1, config_revision_sync
    from services.auto_route_service import AutoRouteService
    monkeypatch.setattr(auto_route_d1, "using_d1", lambda: True)
    with patch.object(config_revision_sync, "route_copy", return_value={"auto:test": (("openai:new",), "time")}), \
            patch.object(auto_route_d1, "stored_routes", side_effect=AssertionError("Legacy read")):
        assert AutoRouteService.get_route("auto:test").candidates == ("openai:new",)


def test_enabled_unverified_authority_stays_closed(monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "d1")
    app = Flask(__name__)
    with patch("services.gateway_extensions.load_settings", return_value=SyncSettings(True)), \
            patch("services.config_revision_sync.control_state_d1.register"), \
            patch("services.config_revision_sync.control_state_d1.ensure_running"):
        register_gateway_extensions(app)
    assert not app.extensions["config_revision_sync"].security_ready()


def test_factory_mounts_single_static_registrar(monkeypatch, tmp_path):
    import importlib
    for name in ("FLASK_SECRET_KEY", "JWT_SECRET", "ADMIN_API_KEY"):
        monkeypatch.setenv(name, "synthetic-revision-test")
    for name in ("AUTH_DB_PATH", "MODEL_REGISTRY_DB_PATH", "RATE_LIMIT_DB_PATH"):
        monkeypatch.setenv(name, str(tmp_path / (name + ".sqlite")))
    monkeypatch.delenv("CONFIG_REVISION_SYNC_ENABLED", raising=False)
    with patch("config.load_runtime_env"), patch("env_loader.load_runtime_env"), \
            patch("services.usage_ledger.start"), patch("requests.Session.send", side_effect=AssertionError("No network")):
        module = importlib.import_module("app")
        with patch.object(module, "load_runtime_env"), patch.object(module, "register_gateway_extensions") as registrar:
            module.create_app()
        assert registrar.call_count == 1


def test_additive_migration_preserves_old_rows_and_rehearses_twice():
    migration = Path(__file__).resolve().parents[1] / "intelligence-migrations/0017_control_revisions.sql"
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE config_snapshot_revisions (domain TEXT PRIMARY KEY, revision INTEGER)")
        db.execute("INSERT INTO config_snapshot_revisions VALUES ('auto_routes', 9)")
        db.executescript(migration.read_text())
        db.executescript(migration.read_text())
        assert db.execute("SELECT revision FROM config_snapshot_revisions").fetchone() == (9,)
        assert db.execute("SELECT COUNT(*) FROM control_revisions").fetchone() == (0,)


def test_malformed_metadata_cannot_renew_freshness():
    sync, now, _, _ = harness(security=True)
    sync.tick()
    now[0] += 5.01
    for invalid in ({"models": True}, {"models": -1}, {"models": 1, "extra": 0}, {"models": 2 ** 60}):
        sync.fetch = lambda domains: invalid
        sync.tick()
        assert not sync.security_ready()
        now[0] += 5


def test_strict_owned_installers_keep_copies_on_authority_failure():
    from services import config_revision_sync, model_override_d1, provider_catalog_d1
    from services.provider_catalog_refresh import refresh_provider_catalog_revision
    with patch.dict(model_override_d1._cache, {"overrides": {"openai:old": "disabled"}, "expires": 0}), \
            patch.object(config_revision_sync.control_state_d1, "call", side_effect=RuntimeError("offline")):
        with pytest.raises(RuntimeError):
            config_revision_sync._refresh_models(1)
        assert model_override_d1._cache["overrides"] == {"openai:old": "disabled"}
    prior = dict(provider_catalog_d1._state)
    with patch.object(config_revision_sync.control_state_d1, "call", side_effect=RuntimeError("offline")):
        with pytest.raises(RuntimeError):
            refresh_provider_catalog_revision(1)
    assert provider_catalog_d1._state == prior


def test_registrar_reuses_one_process_poller_for_repeated_factories(monkeypatch):
    from services import config_revision_sync
    monkeypatch.setattr(config_revision_sync, "_active", None)
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "d1")
    with patch.object(config_revision_sync.control_state_d1, "register") as register, \
            patch.object(config_revision_sync.control_state_d1, "ensure_running"):
        first = config_revision_sync.configure_sync(SyncSettings(True))
        second = config_revision_sync.configure_sync(SyncSettings(True))
    assert first is second
    assert register.call_count == 1


def test_unloaded_new_revision_cannot_be_hidden_by_metadata_rollback():
    sync, now, revisions, _ = harness(security=True)
    sync.tick()
    sync._domains["models"].refresh = Mock(side_effect=RuntimeError("offline"))
    revisions["models"] = 1; now[0] += 5
    sync.tick()
    assert not sync.security_ready()
    revisions["models"] = 0; now[0] += 5
    sync.tick()
    assert not sync.security_ready()


@pytest.mark.parametrize("path", ["/openai/v1/chat/completions", "/googleai/chat/completions",
    "/api/backends/chat-completions/generate", "/intelligence/run", "/optimize/run", "/mcp"])
def test_registered_security_guard_covers_raw_and_special_protocols(path):
    app = Flask(__name__)
    sync, _, _, _ = harness(security=True)
    register_gateway_extensions(app, revision_sync=sync)
    app.add_url_rule(path, "synthetic_dispatch", lambda: {"dispatched": True}, methods=["POST", "OPTIONS"])
    client = app.test_client()
    assert client.post(path).status_code == 503
    assert client.options(path).status_code == 200


def test_guard_keeps_health_accessible():
    app = Flask(__name__)
    sync, _, _, _ = harness(security=True)
    register_gateway_extensions(app, revision_sync=sync)
    app.add_url_rule("/healthz", "health", lambda: {"healthy": True})
    assert app.test_client().get("/healthz").status_code == 200


class AccountAuthority:
    """Private RPC responses captured from an account writer, without network IO."""

    def __init__(self, states):
        self.states, self.index, self.offline = states, 0, False
        self.calls = []

    def __call__(self, payload, *, endpoint):
        self.calls.append((endpoint, payload["operation"]))
        if self.offline:
            raise RuntimeError("Authority unavailable")
        state = self.states[self.index]
        if endpoint == "model_overrides":
            if payload["operation"] == "revisions":
                return {"version": 1, "revisions": {name: state["revisions"].get(name, 0) for name in payload["domains"]}}
            return {"version": 1, "overrides": []}
        if endpoint == "users":
            assert payload["operation"] == "list", "Enabled authentication must use the installed copy"
            users = [row for row in state["users"] if payload["after"] is None or row["username"] > payload["after"]]
            return {"version": 1, "users": users[:payload["limit"]]}
        if endpoint == "auto_routes":
            return {"version": 1, "routes": []}
        if endpoint == "provider_catalog":
            return {"version": 1, "snapshots": []}
        raise AssertionError(endpoint)


def account_states(changes=None):
    from werkzeug.security import generate_password_hash
    from services import user_store
    row = dict.fromkeys(user_store.USER_FIELDS)
    row.update(username="alice", api_key_hash=generate_password_hash("synthetic-revision-key"),
               api_key_prefix="mllm_syntheti", scopes="chat,models", is_admin=0,
               created_at="2026-10-09T00:00:00+00:00")
    return [{"users": [row], "revisions": {"key_controls": 1, "model_grants": 1}},
            {"users": [{**row, **(changes or {"revoked_at": "2026-10-09T01:00:00+00:00"})}],
             "revisions": {"key_controls": 2, "model_grants": 2}}]


def registered_authority(monkeypatch, states, *, enabled=True):
    from flask import request
    from services import auth_service, config_revision_sync, intelligence_d1_store, user_store
    auth = auth_service.AuthService
    authority, now = AccountAuthority(states), [100.0]
    monkeypatch.setenv("CONFIG_REVISION_SYNC_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "d1")
    monkeypatch.setenv("ADMIN_API_KEY", "synthetic-other-admin")
    monkeypatch.setattr(config_revision_sync, "_active", None)
    monkeypatch.setattr(config_revision_sync, "AuthService", auth)
    monkeypatch.setattr(config_revision_sync.control_state_d1, "BACKGROUND", False)
    monkeypatch.setattr(config_revision_sync.control_state_d1, "_tasks", [])
    monkeypatch.setattr(intelligence_d1_store, "request_private_intelligence", authority)
    monkeypatch.setattr(user_store, "request_private_intelligence", authority)
    monkeypatch.setattr(auth, "_users", {})
    monkeypatch.setattr(auth, "_verified_keys", {})
    monkeypatch.setattr(auth, "_api_key_prefix_index", {})
    monkeypatch.setattr(auth, "_update_key_usage", lambda *args: None)
    monkeypatch.setattr("requests.Session.send", Mock(side_effect=AssertionError("No network")))
    app = Flask(__name__)
    app.config["TESTING"] = True
    register_gateway_extensions(app)
    sync = app.extensions.get("config_revision_sync")
    if sync:
        sync.clock, sync.jitter = lambda: now[0], lambda: 0

    @app.get("/v1/probe")
    def probe():
        user = auth.verify_api_key(request.headers.get("X-Test-Key"), "203.0.113.9")
        return ({"user": user}, 200) if user else ({"error": "invalid_api_key"}, 401)

    return app.test_client(), sync, authority, now, auth


def exercise_registered_writer_states(states):
    """Also run by the Worker suite with snapshots read from its real D1 writer."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        client, sync, authority, now, auth = registered_authority(monkeypatch, states)
        headers = {"X-Test-Key": "synthetic-revision-key"}
        assert client.get("/v1/probe", headers=headers).status_code == 503
        sync.tick()
        assert sync.security_ready()
        assert client.get("/v1/probe", headers=headers).status_code == 200
        memo = dict(auth._verified_keys)
        assert memo
        authority.index = 1
        now[0] += 4.1
        sync.tick()
        assert sync.security_ready()
        assert not auth._verified_keys
        assert client.get("/v1/probe", headers=headers).status_code == 401
        assert all(expiry > time.monotonic() for expiry, _ in memo.values())
        authority.offline = True
        now[0] += 5.01
        sync.tick()
        response = client.get("/v1/probe", headers=headers)
        assert response.status_code == 503
        assert response.json["error"]["code"] == "config_security_stale"
        assert response.headers["Cache-Control"] == "no-store"


def test_registered_default_installers_refresh_revoked_keys_and_expired_authority():
    exercise_registered_writer_states(account_states())


@pytest.mark.parametrize("changes", [
    {"scopes": "models", "allowed_models": "openai:new"},
    {"expires_at": "2020-01-01T00:00:00+00:00", "daily_budget_usd": 2},
    {"allowed_ips": "192.0.2.0/24", "monthly_budget_usd": 5},
])
def test_registered_installer_replaces_cached_grants_and_controls(monkeypatch, changes):
    client, sync, authority, now, auth = registered_authority(monkeypatch, account_states(changes))
    sync.tick()
    headers = {"X-Test-Key": "synthetic-revision-key"}
    assert client.get("/v1/probe", headers=headers).status_code == 200
    authority.index = 1
    now[0] += 4.1
    sync.tick()
    assert not auth._verified_keys
    user = client.get("/v1/probe", headers=headers).json["user"]
    for name, value in changes.items():
        assert user[name] == (value.split(",") if name in {"scopes", "allowed_models", "allowed_ips"} else value)


@pytest.mark.parametrize("changes", [{"revoked_at": "invalid"}, {"daily_budget_usd": -1},
    {"allowed_models": "openai:invalid model"}, {"allowed_ips": "garbage"}, {"expires_at": "tomorrow"}])
def test_invalid_account_copy_cannot_certify_security(monkeypatch, changes):
    client, sync, authority, now, auth = registered_authority(monkeypatch, account_states(changes))
    sync.tick()
    authority.index = 1
    now[0] += 4.1
    sync.tick()
    assert not sync.security_ready()
    assert client.get("/v1/probe").status_code == 503
    assert auth._users["alice"]["revoked_at"] is None


@pytest.mark.parametrize("backend,auth_backend", [("", ""), ("sql", "sql"), ("invalid", "d1"), ("d1", "sql"), ("d1", "invalid")])
def test_unsupported_runtime_disables_sync_once(monkeypatch, caplog, backend, auth_backend):
    from services import config_revision_sync
    monkeypatch.setenv("CONFIG_REVISION_SYNC_ENABLED", "true")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", backend)
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", auth_backend)
    monkeypatch.setattr(config_revision_sync, "_warned", set())
    with patch.object(config_revision_sync.control_state_d1, "register") as register:
        for _ in range(2):
            app = Flask(__name__)
            register_gateway_extensions(app)
            assert "config_revision_sync" not in app.extensions
            app.add_url_rule("/v1/probe", "probe", lambda: "unchanged")
            assert app.test_client().get("/v1/probe").data == b"unchanged"
    register.assert_not_called()
    assert sum("requires Container D1" in record.message for record in caplog.records) == 1


def test_flag_off_retains_verified_key_memo_and_legacy_auth(monkeypatch):
    from services import user_store
    client, sync, authority, now, auth = registered_authority(monkeypatch, account_states(), enabled=False)
    assert sync is None
    # The disabled path retains its existing prefix lookup and 60-second memo.
    with patch.object(user_store, "users_by_prefix", return_value=authority.states[0]["users"]) as lookup:
        headers = {"X-Test-Key": "synthetic-revision-key"}
        assert client.get("/v1/probe", headers=headers).status_code == 200
        authority.index = 1
        assert client.get("/v1/probe", headers=headers).status_code == 200
    assert lookup.call_count == 1
    assert authority.calls == []


@pytest.mark.parametrize("mutation", ["delete", "rotate"])
def test_installed_copy_rejects_deleted_or_rotated_memoized_keys(monkeypatch, mutation):
    states = account_states({"api_key_hash": "scrypt:32768:8:1$other$" + "0" * 128,
                             "api_key_prefix": "mllm_rotated"})
    if mutation == "delete":
        states[1]["users"] = []
    exercise_registered_writer_states(states)


def test_explicit_missing_installer_remains_closed_in_d1(monkeypatch):
    client, sync, authority, now, auth = registered_authority(monkeypatch, account_states())
    from services.config_revision_sync import missing_security_refresh
    sync._domains["key_controls"].refresh = missing_security_refresh
    sync.tick()
    assert not sync.security_ready()
    assert client.get("/v1/probe").status_code == 503


def test_security_pages_install_together_and_bad_pagination_preserves_old_copy(monkeypatch):
    from services import key_controls, user_store
    client, sync, authority, now, auth = registered_authority(monkeypatch, account_states())
    monkeypatch.setattr(user_store, "PAGE_SIZE", 1)
    sync.tick()
    assert sync.security_ready()
    assert authority.calls.count(("users", "list")) == 4  # two pages for each security domain
    prior = dict(auth._users)
    row = account_states()[0]["users"][0]
    with patch.object(user_store, "_call", return_value={"version": 1, "users": [row]}):
        with pytest.raises(ValueError, match="pagination"):
            key_controls.refresh_security_copy(auth, 2)
    assert auth._users == prior


@pytest.mark.parametrize("malformed", ["missing_control", "extra_field", "boolean_version", "missing_users", "not_a_list"])
def test_security_copy_rejects_incomplete_private_responses(monkeypatch, malformed):
    from services import key_controls, user_store
    client, sync, authority, now, auth = registered_authority(monkeypatch, account_states())
    sync.tick()
    assert client.get("/v1/probe", headers={"X-Test-Key": "synthetic-revision-key"}).status_code == 200
    prior, memo = dict(auth._users), dict(auth._verified_keys)
    response = {"version": 1, "users": [dict(authority.states[0]["users"][0])]}
    if malformed == "missing_control":
        response["users"][0].pop("shadow_eval_rate")
    elif malformed == "extra_field":
        response["unexpected"] = True
    elif malformed == "boolean_version":
        response["version"] = True
    elif malformed == "missing_users":
        response.pop("users")
    else:
        response["users"] = None
    with patch.object(user_store, "_call", return_value=response):
        with pytest.raises(ValueError):
            key_controls.refresh_security_copy(auth, 2)
    assert auth._users == prior
    assert auth._verified_keys == memo
