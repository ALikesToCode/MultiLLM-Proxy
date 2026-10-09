"""Governance policy, transactional quotas and registered HTTP boundaries."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask, g
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf

from services import tenant_governance as governance, key_controls, budget_service
from services.enterprise_contract import TenantContext
from tests.unified_api_test_case import UnifiedApiTestCase

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)
USER = {"username": "alice", "daily_budget_usd": 1.0, "allowed_models": "openai:*"}
TENANT = TenantContext("alice", "org1", "team1")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "true")
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "false")
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "false")
    path = tmp_path / "governance.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript(Path("intelligence-migrations/0034_tenant_governance.sql").read_text())
    store = governance.SQLiteGovernanceStore(lambda: sqlite3.connect(path, timeout=10))
    app = Flask(__name__)
    app.secret_key = "synthetic-governance-test-secret"
    governance.register_governance_collaborators(app=app, store=store,
        tenant_resolver=lambda user: TenantContext(user["username"], "org1", "team1"),
        membership_role=lambda principal, org: "admin" if org == "org1" else None)
    budget_service.BudgetService.reset()
    yield app, store
    budget_service.BudgetService.reset()


def policy(store, org="org1", team=None, **fields):
    return store.call("put", org_id=org, team_id=team, actor="alice", revision=0,
                      policy={"models": None, "tools": None, "daily": None, "monthly": None, **fields})


@pytest.mark.parametrize("flag", [None, "", "false", "broken"])
def test_disabled_never_resolves_or_reads_storage(setup, monkeypatch, flag):
    app, _ = setup
    if flag is None:
        monkeypatch.delenv("TENANT_GOVERNANCE_ENABLED")
    else:
        monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", flag)
    def forbidden(*args):
        pytest.fail("disabled governance touched authority")
    governance.register_governance_collaborators(app=app, tenant_resolver=forbidden)
    with app.test_request_context():
        assert key_controls.model_allowed(USER, "openai:gpt")
        assert not key_controls.model_allowed(USER, "other:gpt")
        assert not budget_service.budgeted({"username": "alice"})


def test_legacy_remains_unrestricted_by_ancestors(setup):
    app, store = setup
    policy(store, models=[])
    governance.register_governance_collaborators(app=app, store=store)
    with app.test_request_context():
        assert key_controls.model_allowed(USER, "openai:gpt")
        assert not governance.workspace_context(USER)


def test_grants_intersect_key_team_and_organisation_and_tools(setup):
    app, store = setup
    policy(store, models=["openai:*"], tools=["search"])
    policy(store, team="team1", models=["openai:gpt"], tools=[])
    with app.test_request_context():
        assert key_controls.model_allowed(USER, "openai:gpt")
        assert not key_controls.model_allowed(USER, "openai:other")
        assert not key_controls.model_allowed({**USER, "allowed_models": "other:*"}, "openai:gpt")
        assert not governance.grant_allowed(True, "search", user=USER, kind="tools")
        assert not governance.grant_allowed(False, "search", user=USER, kind="tools")


def test_atomic_reject_and_settlement_at_all_levels(setup):
    app, store = setup
    policy(store, daily=1_000_000, monthly=2_000_000)
    policy(store, team="team1", daily=500_000)
    with app.test_request_context():
        first = budget_service.BudgetService.check_and_reserve(USER, 0.4, NOW)
        assert first.allowed
        denied = budget_service.BudgetService.check_and_reserve(USER, 0.2, NOW)
        assert not denied.allowed and denied.error == "tenant_budget_exceeded"
        assert denied.details["level"] == "team"
        assert store.call("usage", context=governance.context_dict(TENANT), role="admin")["holds_micro_usd"] == 400_000
        budget_service.BudgetService.complete(first.reservation,
            {"selected_model": "openai:gpt", "cost_usd": 0.1, "cost_basis": "usage", "status": 200})
        assert budget_service.BudgetService.check_and_reserve(USER, 0.4, NOW).allowed


def test_unknown_holds_survive_settle_and_disabled_flag(setup, monkeypatch):
    app, store = setup
    policy(store, daily=500_000)
    with app.test_request_context():
        first = budget_service.BudgetService.check_and_reserve(USER, 0.4, NOW)
        budget_service.BudgetService.complete(first.reservation, {"cost_usd": None, "cost_basis": None})
        budget_service.BudgetService.settle(first.reservation)
        assert not budget_service.BudgetService.check_and_reserve(USER, 0.2, NOW).allowed
        monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "false")
        budget_service.BudgetService.settle(first.reservation)
    assert store.call("usage", context=governance.context_dict(TENANT), role="admin")["holds_micro_usd"] == 400_000


def test_concurrent_race_has_one_winner_across_connections(setup):
    app, store = setup
    policy(store, daily=500_000)
    def reserve(_):
        with app.test_request_context():
            return budget_service.BudgetService.check_and_reserve(USER, 0.4, NOW)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(8)))
    assert sum(result.allowed for result in results) == 1
    assert sum(result.error == "tenant_budget_exceeded" for result in results) == 7
    assert store.call("usage", context=governance.context_dict(TENANT), role="admin")["holds_micro_usd"] == 400_000


def test_missing_schema_fails_closed_before_key_reservation(setup):
    app, _ = setup
    empty = governance.SQLiteGovernanceStore(lambda: sqlite3.connect(":memory:"))
    governance.register_governance_collaborators(app=app, store=empty, tenant_resolver=lambda user: TENANT)
    with app.test_request_context():
        with pytest.raises(governance.GovernanceError) as failure:
            key_controls.model_allowed(USER, "openai:gpt")
        assert failure.value.code == "tenant_governance_unavailable" and failure.value.status == 503
        decision = budget_service.BudgetService.check_and_reserve(USER, 0.4, NOW)
        assert decision.error == "tenant_governance_unavailable" and decision.status_code == 503
    assert budget_service.BudgetService._reservations == {}


def test_usage_isolation_attribution_and_role_permissions(setup):
    app, store = setup
    policy(store, daily=1_000_000)
    with app.test_request_context():
        first = budget_service.BudgetService.check_and_reserve(USER, 0.2, NOW)
        budget_service.BudgetService.complete(first.reservation,
            {"selected_model": "openai:actual", "cost_usd": 0.1, "cost_basis": "usage"})
        second = budget_service.BudgetService.check_and_reserve({**USER, "username": "bob"}, 0.2, NOW)
        budget_service.BudgetService.complete(second.reservation,
            {"selected_model": "other:actual", "cost_usd": 0.15, "cost_basis": "usage"})
    own = store.call("usage", context=governance.context_dict(TENANT), role="member")
    all_usage = store.call("usage", context=governance.context_dict(TENANT), role="billing")
    foreign = store.call("usage", context=governance.context_dict(TenantContext("alice", "org2")), role="admin")
    assert own["spent_micro_usd"] == 100_000 and all_usage["spent_micro_usd"] == 250_000
    assert foreign["spent_micro_usd"] == 0
    assert own["models"][0]["model"] == "openai:actual" and own["models"][0]["provider"] == "openai"
    assert own["models"][0]["price_basis"] == "usage"
    assert "organisation" not in own and "organisation" in all_usage
    assert not governance.permitted("billing", "edit") and not governance.permitted("member", "budgets")


def test_registered_admin_routes_csrf_cas_and_no_role_writes(setup, monkeypatch):
    app, store = setup
    from routes import usage
    monkeypatch.setattr(usage.AuthService, "get_current_user", lambda: {"username": "alice", "is_admin": True})
    csrf = CSRFProtect(app)
    usage.register_usage_routes(app, csrf)
    @app.route("/test-csrf")
    def csrf_token():
        return {"token": generate_csrf()}
    client = app.test_client()
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user"] = "alice"
    url = "/admin/organisations/org1/governance"
    assert client.get(url).status_code == 200
    assert client.put(url, json={}).status_code == 400
    token = client.get("/test-csrf").json["token"]
    headers = {"X-CSRFToken": token}
    assert client.put(url, json={"daily": 1000}, headers=headers).status_code == 428
    headers["If-Match"] = '"0"'
    updated = client.put(url, json={"daily": 1000}, headers=headers)
    assert updated.status_code == 200 and updated.headers["ETag"] == '"1"'
    assert client.put(url, json={"daily": 2000}, headers=headers).status_code == 412
    headers["If-Match"] = '"1"'
    assert client.put(url, json={"role": "admin"}, headers=headers).status_code == 400
    assert client.get("/admin/organisations/foreign/governance").status_code == 403
    with store.connect() as db:
        audit = db.execute("SELECT * FROM tenant_governance_audit").fetchall()
    assert len(audit) == 1
    monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "false")
    assert client.get(url).status_code == 404 and client.put(url, json={}).status_code == 404


def test_auto_eligibility_uses_same_intersection(setup, monkeypatch):
    app, store = setup
    from services import intelligence_policy
    policy(store, models=[])
    monkeypatch.setattr(intelligence_policy, "get_adapter", lambda *args: object())
    candidate = {"model": "openai:gpt", "enabled": True, "entitled": True, "privacy_allowed": True, "billing": "free"}
    with app.test_request_context():
        g.authenticated_user = USER
        assert not intelligence_policy.eligible(candidate, False, {"API_BASE_URLS": {}}, model_status=lambda _: "enabled")


def test_missing_column_no_partial_state_and_repeatable_migration(setup):
    app, store = setup
    with store.connect() as db:
        db.execute("CREATE TABLE old_rows (value TEXT)")
        db.execute("INSERT INTO old_rows VALUES ('preserved')")
        db.executescript(Path("intelligence-migrations/0034_tenant_governance.sql").read_text())
        assert db.execute("SELECT value FROM old_rows").fetchone()[0] == "preserved"
        db.execute("ALTER TABLE tenant_governance_policies RENAME COLUMN models TO old_models")
    with app.test_request_context():
        result = budget_service.BudgetService.check_and_reserve(USER, 0.4, NOW)
        assert result.status_code == 503
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM tenant_governance_reservations").fetchone()[0] == 0


def test_key_reject_is_atomic_and_unknown_price_denied(setup):
    app, store = setup
    policy(store, daily=1_000_000)
    with app.test_request_context():
        result = budget_service.BudgetService.check_and_reserve({**USER, "daily_budget_usd": 0.1}, 0.4, NOW)
        assert result.error == "budget_exceeded"
        assert budget_service.BudgetService.check_and_reserve(USER, None, NOW).error == "unpriced_reservation"
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM tenant_governance_components").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM tenant_governance_baselines").fetchone()[0] == 0


def test_resolver_cannot_change_principal_and_role_defaults_to_denied(setup):
    app, store = setup
    governance.register_governance_collaborators(app=app, store=store, tenant_resolver=lambda user: TenantContext("bob", "org1"))
    with app.test_request_context():
        with pytest.raises(governance.GovernanceError) as failure:
            governance.workspace_context(USER)
        assert failure.value.status == 403
    governance.register_governance_collaborators(app=app, store=store, tenant_resolver=lambda user: TENANT)
    with app.test_request_context():
        with pytest.raises(governance.GovernanceError) as failure:
            governance.workspace_usage(USER)
        assert failure.value.status == 403


def test_invalid_flag_warns_once_without_value(monkeypatch, caplog):
    governance._warn_once.cache_clear()
    monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "sensitive-invalid-value")
    assert not governance.enabled() and not governance.enabled()
    messages = [record.message for record in caplog.records if "TENANT_GOVERNANCE_ENABLED" in record.message]
    assert len(messages) == 1 and "sensitive-invalid-value" not in messages[0]


def test_private_adapter_preserves_ancestor_denial_level_without_replaying(setup, monkeypatch):
    app, _ = setup
    calls = []
    monkeypatch.setattr(governance.control_state_d1, "using_d1", lambda: True)
    def remote(endpoint, operation, **values):
        calls.append((endpoint, operation, values))
        return {"version": 1, "decision": {"allowed": False, "code": "tenant_budget_exceeded",
                                           "status": 429, "level": "team", "period": "daily"}}
    monkeypatch.setattr(governance.control_state_d1, "call", remote)
    with app.test_request_context():
        with pytest.raises(governance.GovernanceError) as failure:
            governance.D1GovernanceStore().call("reserve", id="tg_test")
    assert failure.value.code == "tenant_budget_exceeded" and failure.value.level == "team"
    assert len(calls) == 1 and calls[0][0] == "tenant_governance" and calls[0][2]["rpc"] is True


def test_python_conflicting_settlement_cannot_replace_cost(setup):
    app, _ = setup
    with app.test_request_context():
        first = budget_service.BudgetService.check_and_reserve(USER, 0.4, NOW)
        row = {"selected_model": "openai:gpt", "cost_usd": 0.1, "cost_basis": "usage"}
        budget_service.BudgetService.complete(first.reservation, row)
        budget_service.BudgetService.complete(first.reservation, row)
        with pytest.raises(governance.GovernanceError) as failure:
            budget_service.BudgetService.complete(first.reservation, {**row, "cost_usd": 0.2})
        assert failure.value.status == 409


def test_billing_can_read_but_not_write_policy(setup, monkeypatch):
    app, store = setup
    from routes import usage
    monkeypatch.setattr(usage.AuthService, "get_current_user", lambda: {"username": "alice", "is_admin": True})
    governance.register_governance_collaborators(app=app, store=store,
        tenant_resolver=lambda user: TENANT, membership_role=lambda principal, org: "billing")
    app.config["WTF_CSRF_ENABLED"] = False
    usage.register_usage_routes(app, CSRFProtect(app))
    client = app.test_client()
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user"] = "alice"
    url = "/admin/organisations/org1/teams/team1/governance"
    assert client.get(url).status_code == 200
    assert client.put(url, json={"daily": 1}, headers={"If-Match": '"0"'}).status_code == 403


class RegisteredGovernanceTest(UnifiedApiTestCase):
    def setUp(self):
        with patch("config.load_runtime_env", lambda: None):
            super().setUp()
        import os
        os.environ.update({"TENANT_GOVERNANCE_ENABLED": "true", "USAGE_RESERVATIONS_ENABLED": "false",
                           "USAGE_LEDGER_ENABLED": "false", "MODEL_PRICING_USD_PER_MILLION": '{"opencode:*":{"input":1000,"output":1000}}'})
        self.path = Path(self.temp_dir.name) / "governance.sqlite3"
        with sqlite3.connect(self.path) as db:
            db.executescript(Path("intelligence-migrations/0034_tenant_governance.sql").read_text())
        self.store = governance.SQLiteGovernanceStore(lambda: sqlite3.connect(self.path))
        governance.register_governance_collaborators(app=self.app, store=self.store,
            tenant_resolver=lambda user: TenantContext(user["username"], "org1", "team1"),
            membership_role=lambda principal, org: "member")
        with patch.object(self.app_module.AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            self.key = self.app_module.AuthService.create_user("alice", scopes=["chat", "models"])["api_key"]
        budget_service.BudgetService.reset()

    def tearDown(self):
        budget_service.BudgetService.reset()
        super().tearDown()

    def chat(self):
        response = self._chat_response()
        response._content = b'{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":7}}'
        with patch.object(self.app_module.ProxyService, "make_request", return_value=response) as upstream:
            result = self.client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {self.key}"},
                json={"model": "opencode:glm-5.2", "messages": [{"role": "user", "content": "test"}], "max_tokens": 5}, buffered=True)
        return result, upstream

    def test_missing_table_refuses_real_route_before_upstream(self):
        governance.register_governance_collaborators(app=self.app,
            store=governance.SQLiteGovernanceStore(lambda: sqlite3.connect(":memory:")),
            tenant_resolver=lambda user: TENANT)
        response, upstream = self.chat()
        assert response.status_code == 503 and response.json["error"]["code"] == "tenant_governance_unavailable"
        upstream.assert_not_called()

    def test_workspace_budget_envelope_and_success_attribution(self):
        policy(self.store, daily=1_000_000)
        response, upstream = self.chat()
        assert response.status_code == 200
        upstream.assert_called_once()
        with self.store.connect() as db:
            row = db.execute("SELECT provider,model,price_basis,charged FROM tenant_governance_reservations").fetchone()
        assert row == ("opencode", "opencode:glm-5.2", "usage", 12000)
        self.store.call("put", org_id="org1", team_id=None, actor="alice", revision=1,
                        policy={"daily": 12000})
        denied, upstream = self.chat()
        assert denied.status_code == 429 and denied.json["error"]["code"] == "tenant_budget_exceeded"
        assert denied.json["error"]["level"] == "organisation"
        upstream.assert_not_called()

    def test_usage_route_never_reads_unscoped_history(self):
        from routes import usage
        with patch.object(usage, "usage_history", side_effect=AssertionError("unscoped history")):
            result = self.client.get("/v1/usage", headers={"Authorization": f"Bearer {self.key}"})
        assert result.status_code == 200 and result.json["workspace"]["org_id"] == "org1"
        assert result.json["workspace"]["spent_micro_usd"] == 0

    def test_disabled_and_legacy_usage_are_identical(self):
        import os
        os.environ["TENANT_GOVERNANCE_ENABLED"] = "false"
        disabled = self.client.get("/v1/usage", headers={"Authorization": f"Bearer {self.key}"})
        os.environ["TENANT_GOVERNANCE_ENABLED"] = "true"
        governance.register_governance_collaborators(app=self.app, store=self.store)
        legacy = self.client.get("/v1/usage", headers={"Authorization": f"Bearer {self.key}"})
        assert disabled.status_code == legacy.status_code == 200 and disabled.data == legacy.data


def test_shared_reconciliation_vectors_keep_unknown_holds_and_settle_once(setup):
    import json
    app, store = setup
    identity = "tg_reconciliation"
    store.call("reserve", id=identity, context=governance.context_dict(TENANT), amount=400000,
               day="2026-10-09", month="2026-10", key_daily=1000000, key_monthly=None,
               base_day=0, base_month=0)
    store.call("dispatch", id=identity)
    store.call("settle", id=identity, cost=None)
    vectors = json.loads(Path("tests/fixtures/governance_reconciliation.json").read_text())
    for vector in vectors:
        values = {key: value for key, value in vector.items() if not key.startswith("expected_") and key not in {"error", "status"}}
        if "error" in vector:
            with pytest.raises(governance.GovernanceError) as failure:
                store.call("reconcile", id=identity, **values)
            assert (failure.value.code, failure.value.status) == (vector["error"], vector["status"])
        else:
            result = store.call("reconcile", id=identity, **values)
            assert result["applied"] is vector["expected_applied"]
            assert result["reservation"]["state"] == vector["expected_state"]
            totals = store.call("usage", context=governance.context_dict(TENANT), role="admin")
            assert totals["holds_micro_usd"] == (400000 if vector["cost"] is None else 0)
            assert totals["spent_micro_usd"] == (0 if vector["cost"] is None else 100000)
