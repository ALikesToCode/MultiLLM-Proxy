"""Request admission and workspace isolation with synthetic storage and upstreams."""
import hashlib
import importlib
import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask, g, jsonify

from tests.test_wave5_managed import gateway as base_gateway, body, post
from tests.test_protocol_routes import RESPONSES_BODY, CHAT_STREAM, json_upstream, sse_upstream

FLAGS = ("ORGANISATIONS_ENABLED", "TENANT_GOVERNANCE_ENABLED", "SAML_ENABLED",
         "SCIM_ENABLED", "CREDITS_ENABLED", "PAYMENTS_ENABLED")


@pytest.fixture(autouse=True)
def defaults(monkeypatch):
    for flag in FLAGS:
        monkeypatch.setenv(flag, "false")
    monkeypatch.setenv("CREDITS_ENFORCEMENT", "off")
    monkeypatch.setenv("AUTH_STORAGE_BACKEND", "")
    for flag in ("HEDGED_REQUESTS_ENABLED", "STREAM_COST_BREAKER_ENABLED", "USAGE_RECEIPTS_ENABLED"):
        monkeypatch.setenv(flag, "false")
    monkeypatch.setenv("CONTEXT_CANARY_MODE", "off")
    monkeypatch.setenv("LATENCY_SLO_MODE", "off")


@pytest.fixture
def gateway(base_gateway):
    base_gateway.headers["X-Request-ID"] = "managed-fixed"
    return base_gateway


@pytest.fixture
def credits(tmp_path, monkeypatch):
    admission = importlib.import_module("services.credits_admission")
    ledger = importlib.import_module("services.credits_ledger")
    contracts = importlib.import_module("services.enterprise_contract")
    path = tmp_path / "credits.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript(Path("intelligence-migrations/0037_credits_ledger.sql").read_text())
    store = ledger.SqlCreditsLedger(path)
    monkeypatch.setenv("CREDITS_ENABLED", "true")
    monkeypatch.setenv("CREDITS_ENFORCEMENT", "all")
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", '{"mimo:mimo-v2.5":{"input":1,"output":1}}')
    monkeypatch.setattr(admission.credits_ledger, "open_store", lambda: store)
    app = Flask(__name__)
    app.config["TESTING"] = True
    authority = admission.register_credits_admission(app)
    app.extensions["enterprise_adapters"] = contracts.register_enterprise_adapters(credit=authority)
    return app, store, admission, contracts


def fund(store, owner="alice", amount=1000):
    store.append(owner, "credit", amount, "fund", 0)


@pytest.mark.parametrize("mode", ["funded", "all"])
def test_reserve_commit_and_unknown_hold(credits, monkeypatch, mode):
    app, store, admission, contracts = credits
    monkeypatch.setenv("CREDITS_ENFORCEMENT", mode)
    fund(store)
    with app.test_request_context("/v1/chat/completions"):
        g.authenticated_user = {"username": "alice"}
        hold = admission.reserve(0.0001, scoped_id="attempt1")
        assert store.read("alice")["held_microusd"] == 100
        admission.mark_dispatched(hold)
        admission.complete(hold, {"cost_usd": 0.000025, "cost_basis": "usage"})
        admission.complete(hold, {"cost_usd": 0.000025, "cost_basis": "usage"})
        assert store.read("alice")["balance_microusd"] == 975
        unknown = admission.reserve(0.0001, scoped_id="attempt2")
        admission.mark_dispatched(unknown)
        admission.complete(unknown, {"cost_usd": None, "cost_basis": None})
        admission.complete(unknown, {})
    rows = store.read("alice")
    assert rows["held_microusd"] == 100
    assert [entry["kind"] for entry in rows["entries"]] == ["credit", "reserve", "commit", "reserve", "reserve"]


def test_funded_unfunded_and_enforcement_off_never_charge(credits, monkeypatch):
    app, store, admission, _ = credits
    with app.test_request_context():
        g.authenticated_user = {"username": "alice"}
        monkeypatch.setenv("CREDITS_ENFORCEMENT", "funded")
        assert admission.reserve(None, scoped_id="unfunded") is None
        monkeypatch.setenv("CREDITS_ENFORCEMENT", "off")
        with patch.object(store, "read", side_effect=AssertionError("enforcement off read credits")):
            assert admission.reserve(None, scoped_id="disabled") is None


@pytest.mark.parametrize("estimate,code,status", [(None, "credits_unpriced", 503), (0, "credits_unpriced", 503),
                                                    (0.001001, "credits_insufficient", 402)])
def test_credit_denials_are_predispatch(credits, estimate, code, status):
    app, store, admission, _ = credits
    fund(store)
    with app.test_request_context():
        g.authenticated_user = {"username": "alice"}
        with pytest.raises(admission.CreditAdmissionError) as failure:
            admission.reserve(estimate, scoped_id="denied")
        assert failure.value.code == code and failure.value.status == status
    assert store.read("alice")["held_microusd"] == 0


def test_revision_retry_keeps_operation_identity(credits, monkeypatch):
    app, store, admission, contracts = credits
    fund(store)
    original = store.append
    attempts = []
    def append(*args, **kwargs):
        attempts.append((args, kwargs))
        if len(attempts) == 1:
            original("alice", "adjust", 1, "concurrent", 1, actor="admin", reason="allocation")
        return original(*args, **kwargs)
    monkeypatch.setattr(store, "append", append)
    with app.test_request_context():
        g.authenticated_user = {"username": "alice"}
        hold = admission.reserve(0.0001, scoped_id="same-attempt")
        admission.release(hold)
        admission.release(hold)
    assert len(attempts) == 3
    assert attempts[0][0][3] == attempts[1][0][3]
    assert attempts[0][0][4] == 1 and attempts[1][0][4] == 2
    assert attempts[0][1]["scoped_id"] == attempts[1][1]["scoped_id"] == "same-attempt"
    assert store.read("alice")["held_microusd"] == 0
    assert store.read("alice")["entries"][-1]["kind"] == "release"


@pytest.mark.parametrize("path,payload,result", [
    ("/v1/chat/completions", body(), None),
    ("/v1/messages", {"model": "mimo:mimo-v2.5", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 10}, None),
    ("/v1/responses", {"model": "opencode:grok-4.6", "input": "hi"}, RESPONSES_BODY),
    ("/v1/chat/completions", body(model="auto:managed-test"), None),
    ("/v1/chat/completions", body(model="opencode:kimi-k2.6", stream=True), "stream"),
])
def test_flags_off_keep_registered_request_bytes(gateway, monkeypatch, path, payload, result):
    monkeypatch.setattr("time.perf_counter", lambda: 1000)
    importlib.import_module("services.auto_route_service").AutoRouteService.save_route(
        "auto:managed-test", ["mimo:mimo-v2.5"], gateway.app.config["API_BASE_URLS"])
    def reply():
        return sse_upstream(CHAT_STREAM) if result == "stream" else json_upstream(result) if result else gateway._chat_response()
    first, send = post(gateway, payload, path=path, reply=reply())
    submitted = send.call_args.kwargs["data"]
    for flag in (*FLAGS, "CREDITS_ENFORCEMENT"):
        monkeypatch.delenv(flag, raising=False)
    second, send = post(gateway, payload, path=path, reply=reply())
    assert first.status_code == second.status_code == 200
    assert first.data == second.data and submitted == send.call_args.kwargs["data"]
    assert list(first.headers) == list(second.headers)


def test_legacy_namespace_bytes_and_workspace_separation(monkeypatch):
    contracts = importlib.import_module("services.enterprise_contract")
    shared = importlib.import_module("services.shared_generation_cache")
    semantic = importlib.import_module("services.semantic_generation_cache")
    idempotency = importlib.import_module("services.idempotency_store")
    responses = importlib.import_module("services.responses_state")
    pages = importlib.import_module("services.context_pages")
    accounting = importlib.import_module("services.request_accounting")
    app = Flask(__name__)
    user = {"username": "alice", "id": 7}
    policy = importlib.import_module("services.cache_policy").CachePolicy("openai:gpt", "1", "1", "1", "1")
    payload = body()
    with app.test_request_context("/v1/chat/completions", headers={"Authorization": "Bearer synthetic", "Session-Id": "session"}, json=payload):
        g.authenticated_user = user
        principal = "alice\0key-hash"
        scope, digest = idempotency.request_fingerprint("alice", "POST", "/v1/chat/completions", "id", payload, "1")
        assert scope == hashlib.sha256(idempotency._canonical(["alice", "POST", "/v1/chat/completions", "id"])).hexdigest()
        assert digest == hashlib.sha256(idempotency._canonical([payload, "1"])).hexdigest()
        assert responses.principal_owner() == hashlib.sha256(responses.canonical([None, "7"])).hexdigest()
        legacy = shared.identity(principal, payload, policy)
        assert legacy["principal_hash"] == hashlib.sha256(principal.encode()).hexdigest()
        legacy_semantic = semantic.partition(principal, "/v1/chat/completions", payload, {}, {})
        legacy_pages = pages.managed_authority()["scope"].principal
        context = accounting.UsageContext("chat", [payload["model"]], None, user, 1000, 1)
        row = accounting._row(context, 200, None, None)
        assert row["principal"] == "alice" and "workspace" not in row
        snapshots = []
        for org in ("one", "two"):
            g.tenant_context = contracts.TenantContext("alice", org, "team")
            snapshots.append((shared.identity(principal, payload, policy),
                semantic.partition(principal, "/v1/chat/completions", payload, {}, {}),
                idempotency.request_fingerprint("alice", "POST", "/v1/chat/completions", "id", payload, "1"),
                responses.principal_owner(), pages.managed_authority()["scope"]))
        assert all(a != b for a, b in zip(*snapshots))
        assert snapshots[0][0] != legacy and snapshots[0][1] != legacy_semantic
        assert snapshots[0][4].principal != legacy_pages


@pytest.mark.parametrize("mode", ["off", "funded", "all"])
def test_registered_charged_generation(gateway, credits, monkeypatch, mode):
    _, store, admission, _ = credits
    gateway.app.extensions.update(credits[0].extensions)
    monkeypatch.setenv("CREDITS_ENFORCEMENT", mode)
    monkeypatch.setenv("RESPONSE_CACHE_ENABLED", "false")
    fund(store, "admin", 10000)
    response, send = post(gateway, reply=json_upstream({"model": "mimo:mimo-v2.5",
        "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20}}))
    assert response.status_code == 200, response.data
    assert send.call_count == 1
    rows = store.read("admin")
    assert rows["held_microusd"] == 0
    assert [entry["kind"] for entry in rows["entries"]] == (["credit"] if mode == "off" else ["credit", "reserve", "commit"])


def test_governance_denial_precedes_credits_and_lazy_completion(credits, tmp_path, monkeypatch):
    app, store, admission, contracts = credits
    governance = importlib.import_module("services.tenant_governance")
    accounting = importlib.import_module("services.request_accounting")
    budget = importlib.import_module("services.budget_service")
    path = tmp_path / "governance.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript(Path("intelligence-migrations/0034_tenant_governance.sql").read_text())
    authority = governance.SQLiteGovernanceStore(lambda: sqlite3.connect(path))
    tenant = contracts.TenantContext("alice", "org", "team")
    governance.register_governance_collaborators(app=app, store=authority, tenant_resolver=lambda user: tenant)
    monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "true")
    authority.call("put", org_id="org", team_id=None, actor="alice", revision=0,
                   policy={"models": None, "tools": None, "daily": 0, "monthly": None})
    fund(store, admission.owner(tenant), 10000)
    budget.BudgetService.reset()
    with app.test_request_context("/v1/chat/completions", method="POST", json=body()):
        g.authenticated_user = {"username": "alice"}
        g.tenant_context = tenant
        with patch.object(store, "append", wraps=store.append) as append:
            denied = accounting.begin()
            assert denied.status_code == 429 and denied.json["error"] == "tenant_budget_exceeded"
            append.assert_not_called()
        authority.call("put", org_id="org", team_id=None, actor="alice", revision=1,
                       policy={"models": None, "tools": None, "daily": 10000, "monthly": None})
        assert accounting.begin() is None
        context = g.usage_context
        accounting.mark_dispatched()
    accounting._record_budget(context, {"cost_usd": 0.000025, "cost_basis": "usage", "status": 200,
                                         "selected_model": "mimo:mimo-v2.5"})
    totals = authority.call("usage", context=governance.context_dict(tenant), role="admin")
    assert totals["holds_micro_usd"] == 0 and totals["spent_micro_usd"] == 25
    assert store.read(admission.owner(tenant))["balance_microusd"] == 9975
    budget.BudgetService.reset()


def test_unknown_durable_reconciliation_charges_once(credits, tmp_path, monkeypatch):
    app, store, admission, _ = credits
    reservations = importlib.import_module("services.reservation_store")
    durable = reservations.SqlReservationStore(tmp_path / "usage.sqlite3")
    identity = "a" * 32
    transition = "b" * 32
    durable.reserve(identity, "alice", 0.0001, 1, None, 0, 0)
    fund(store)
    with app.test_request_context():
        g.authenticated_user = {"username": "alice"}
        hold = admission.reserve(0.0001, scoped_id=identity)
        admission.mark_dispatched(hold)
        admission.complete(hold, {})
        durable.transition(identity, 0, "dispatched", transition_id="c" * 32)
        durable.transition(identity, 1, "unknown", transition_id="d" * 32)
        for _ in range(2):
            reservations.reconcile(durable, identity, 2, 0.000025, admin=True, reason="provider_usage",
                                   evidence="receipt1", transition_id=transition)
    assert store.read("alice")["balance_microusd"] == 975
    assert store.read("alice")["held_microusd"] == 0
    assert len([entry for entry in store.read("alice")["entries"] if entry["kind"] == "commit"]) == 1


def test_isolated_attempts_bind_distinct_scopes(credits):
    app, store, admission, _ = credits
    managed = importlib.import_module("services.managed_dispatch")
    fund(store)
    with app.test_request_context():
        g.authenticated_user = {"username": "alice"}
        identities = []
        for _ in range(2):
            with managed.isolated_managed_attempt(None):
                hold = admission.reserve(0.0001, scoped_id=managed.current_attempt_id())
                identities.append(hold.scoped_id)
                admission.release(hold)
        assert managed.current_attempt_id() is None
    assert identities[0] != identities[1] and store.read("alice")["held_microusd"] == 0


def test_pre_dispatch_rejection_releases_request_once(credits):
    app, store, admission, _ = credits
    accounting = importlib.import_module("services.request_accounting")
    fund(store)
    with app.test_request_context("/v1/chat/completions", method="POST", json=body()):
        g.authenticated_user = {"username": "alice"}
        assert accounting.begin() is None
        assert store.read("alice")["held_microusd"] > 0
        accounting.release_before_dispatch()
        accounting.release_before_dispatch()
    assert store.read("alice")["held_microusd"] == 0
    assert [entry["kind"] for entry in store.read("alice")["entries"]] == ["credit", "reserve", "release"]


def test_conflict_is_not_retried_and_settlement_retains_hold(credits, monkeypatch):
    app, store, admission, _ = credits
    ledger = importlib.import_module("services.credits_ledger")
    fund(store)
    with app.test_request_context():
        g.authenticated_user = {"username": "alice"}
        hold = admission.reserve(0.0001, scoped_id="attempt")
        admission.mark_dispatched(hold)
        with patch.object(store, "append", side_effect=ledger.CreditsError("credits_conflict", 409)) as append:
            with pytest.raises(admission.CreditAdmissionError) as error:
                admission.complete(hold, {"cost_usd": 0.000025, "cost_basis": "usage"})
            assert error.value.code == "credits_unavailable" and append.call_count == 1
        assert not hold.terminal and store.read("alice")["held_microusd"] == 100


@pytest.mark.parametrize("workspace", [False, True])
def test_hedged_attempts_own_separate_credit_settlement(credits, tmp_path, monkeypatch, workspace):
    import threading
    from flask import Response
    app, store, admission, contracts = credits
    accounting = importlib.import_module("services.request_accounting")
    hedges = importlib.import_module("services.hedged_requests")
    budget = importlib.import_module("services.budget_service")
    reservations = importlib.import_module("services.reservation_store")
    governance = importlib.import_module("services.tenant_governance")
    tenant = contracts.TenantContext("alice", "org", "team") if workspace else contracts.TenantContext("alice")
    authority = None
    if workspace:
        path = tmp_path / "governance.sqlite3"
        with sqlite3.connect(path) as db:
            db.executescript(Path("intelligence-migrations/0034_tenant_governance.sql").read_text())
        authority = governance.SQLiteGovernanceStore(lambda: sqlite3.connect(path))
        governance.register_governance_collaborators(app=app, store=authority, tenant_resolver=lambda user: tenant)
        monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "true")
    fund(store, admission.owner(tenant))
    models = ["mimo:mimo-v2.5", "opencode:second"]
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", json.dumps({model: {"input": 1, "output": 1} for model in models}))
    budget.BudgetService.reset()
    with app.test_request_context("/v1/chat/completions", method="POST", json=body()):
        g.authenticated_user = {"username": "alice", "daily_budget_usd": 1}
        g.tenant_context = tenant
        assert accounting.begin() is None
        outer = g.usage_context
        # The legacy in-memory budget hold has the same undispatched bounds.
        with patch.object(reservations, "get_store") as durable:
            durable.return_value.get.return_value = {"state": "reserved", "estimate_usd": outer.estimate}
            holds = hedges._prepare_holds(models, body())
        attempts = [hedges._Attempt(model, i, holds[i], outer, 1010, lambda: 1000, threading.Condition())
                    for i, model in enumerate(models)]
        assert attempts[0].context.credit_hold.scoped_id != attempts[1].context.credit_hold.scoped_id
        for attempt in attempts:
            attempt._dispatch_started()
            attempt.response = Response(status=200)
        attempts[0].accepted = True
        attempts[0].usage = accounting.UsageObservation(10, 20, "provider", ("provider",))
        attempts[1].cancel()
        for attempt in attempts:
            attempt._settle()
    rows = store.read(admission.owner(tenant))
    assert rows["held_microusd"] == 0 and rows["balance_microusd"] == 970
    assert [entry["kind"] for entry in rows["entries"]] == ["credit", "reserve", "reserve", "commit", "release"]
    if workspace:
        totals = authority.call("usage", context=governance.context_dict(tenant), role="admin")
        assert totals["requests"] == 2 and totals["holds_micro_usd"] == 0 and totals["spent_micro_usd"] == 30
    budget.BudgetService.reset()


def test_background_item_cannot_fall_back_to_legacy_workspace(credits, monkeypatch):
    app, store, admission, _ = credits
    accounting = importlib.import_module("services.request_accounting")
    monkeypatch.setenv("ORGANISATIONS_ENABLED", "true")
    with app.test_request_context():
        g.authenticated_user = {"username": "alice"}
        with patch.object(store, "read", side_effect=AssertionError("unverified item touched credits")):
            error, identity = accounting.admit_item(g.authenticated_user, "mimo:mimo-v2.5", 1)
        assert error["status"] == 503 and error["code"] == "tenant_storage_unavailable"
        assert identity is None


def test_revision_mismatch_stops_after_three_total_attempts(credits):
    app, store, admission, _ = credits
    ledger = importlib.import_module("services.credits_ledger")
    fund(store)
    with app.test_request_context():
        g.authenticated_user = {"username": "alice"}
        with patch.object(store, "read", wraps=store.read) as reads, patch.object(
                store, "append", side_effect=ledger.CreditsError("credits_revision_mismatch", 412)) as writes:
            with pytest.raises(admission.CreditAdmissionError) as error:
                admission.reserve(0.0001, scoped_id="attempt")
            assert error.value.code == "credits_unavailable"
            assert reads.call_count == writes.call_count == 3
            assert len({call.args[3] for call in writes.call_args_list}) == 1
            assert len({call.kwargs["scoped_id"] for call in writes.call_args_list}) == 1
    assert store.read("alice")["held_microusd"] == 0


@pytest.mark.parametrize("workspace", [False, True])
def test_gateway_subrequests_replace_outer_holds_once(credits, tmp_path, monkeypatch, workspace):
    from flask import Response
    app, ledger, admission, contracts = credits
    accounting = importlib.import_module("services.request_accounting")
    dispatch = importlib.import_module("services.accounted_dispatch")
    governance = importlib.import_module("services.tenant_governance")
    budget = importlib.import_module("services.budget_service")
    tenant = contracts.TenantContext("alice", "org", "team") if workspace else contracts.TenantContext("alice")
    authority = None
    if workspace:
        path = tmp_path / "governance.sqlite3"
        with sqlite3.connect(path) as db:
            db.executescript(Path("intelligence-migrations/0034_tenant_governance.sql").read_text())
        authority = governance.SQLiteGovernanceStore(lambda: sqlite3.connect(path))
        governance.register_governance_collaborators(app=app, store=authority, tenant_resolver=lambda user: tenant)
        monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "true")
    fund(ledger, admission.owner(tenant), 10000)
    budget.BudgetService.reset()
    with app.test_request_context("/v1/chat/completions", method="POST", json=body()):
        g.authenticated_user = {"username": "alice"}
        g.tenant_context = tenant
        assert accounting.begin() is None
        outer = g.usage_context
        dispatch.release_outer_accounting()
        dispatch.release_outer_accounting()
        def send(payload):
            accounting.mark_dispatched()
            return Response(json.dumps({"usage": {"prompt_tokens": 10, "completion_tokens": 20}}), mimetype="application/json")
        for _ in range(2):
            assert dispatch.accounted_dispatch(body(), send, kind="chat", skip_rate=True).status_code == 200
        assert outer.finished
    entries = ledger.read(admission.owner(tenant))
    assert entries["held_microusd"] == 0 and entries["balance_microusd"] == 9940
    reserves = [e for e in entries["entries"] if e["kind"] == "reserve"]
    assert len(reserves) == 3 and len({e["scoped_id"] for e in reserves}) == 3
    assert len([e for e in entries["entries"] if e["kind"] == "release"]) == 1
    if authority:
        totals = authority.call("usage", context=governance.context_dict(tenant), role="admin")
        assert totals["spent_micro_usd"] == 60 and totals["holds_micro_usd"] == 0
    budget.BudgetService.reset()


def test_local_exact_cache_namespaces_keep_legacy_bytes(monkeypatch):
    cache = importlib.import_module("routes.chat_cache")
    contracts = importlib.import_module("services.enterprise_contract")
    app = Flask(__name__)
    payload = body()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    expected = hashlib.sha256("\0".join(("alice", "/v1/chat/completions", canonical)).encode()).hexdigest()
    with app.test_request_context():
        assert cache.cache_key("alice", "/v1/chat/completions", payload) == expected
        keys = []
        for org in ("one", "two"):
            g.tenant_context = contracts.TenantContext("alice", org)
            keys.append(cache.cache_key("alice", "/v1/chat/completions", payload))
        assert len(set([expected, *keys])) == 3


def test_signed_background_capability_captures_verified_workspace(monkeypatch):
    signing = importlib.import_module("services.media_signing")
    hierarchy = importlib.import_module("services.tenant_hierarchy")
    contracts = importlib.import_module("services.enterprise_contract")
    monkeypatch.setenv("MEDIA_SIGNING_SECRET", "synthetic-background-secret")
    monkeypatch.setenv("ORGANISATIONS_ENABLED", "true")
    app = Flask(__name__)
    tenant = contracts.TenantContext("alice", "submitted-org", "team", 7)
    with app.test_request_context():
        g.tenant_context = tenant
        token = signing.issue_principal("batch", "job", "alice", 60)
    with app.test_request_context():
        claims = signing.read_principal(token, "batch")
        g.authenticated_user = {"username": "alice"}
        with patch.object(hierarchy, "resolve_principal", side_effect=AssertionError("Background resolved workspace")):
            signing.bind_principal_tenant(claims, g.authenticated_user)
            assert hierarchy.tenant_context_hook() is None
        assert hierarchy.current_tenant() == tenant


def test_background_capability_without_workspace_fails_closed(monkeypatch):
    signing = importlib.import_module("services.media_signing")
    monkeypatch.setenv("MEDIA_SIGNING_SECRET", "synthetic-background-secret")
    monkeypatch.setenv("ORGANISATIONS_ENABLED", "false")
    token = signing.issue_principal("batch", "job", "alice", 60)
    claims = signing.read_principal(token, "batch")
    assert set(claims) == {"k", "s", "o", "e"}
    monkeypatch.setenv("ORGANISATIONS_ENABLED", "true")
    with Flask(__name__).test_request_context():
        with pytest.raises(Exception) as error:
            signing.bind_principal_tenant(claims, {"username": "alice"})
        assert error.value.status_code == 503


def test_governance_reconciliation_repairs_credit_settlement_after_restart(credits, tmp_path, monkeypatch):
    app, ledger, admission, contracts = credits
    governance = importlib.import_module("services.tenant_governance")
    reservations = importlib.import_module("services.reservation_store")
    path = tmp_path / "governance.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript(Path("intelligence-migrations/0034_tenant_governance.sql").read_text())
    authority = governance.SQLiteGovernanceStore(lambda: sqlite3.connect(path))
    context = contracts.TenantContext("alice", "submitted", "team", 4)
    governance.register_governance_collaborators(app=app, store=authority,
        tenant_resolver=lambda _: pytest.fail("reconciliation resolved a tenant"))
    monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "true")
    fund(ledger, admission.owner(context), 1000)
    identity = "tg_restart"
    authority.call("reserve", id=identity, context=governance.context_dict(context), amount=100,
        day="2026-10-09", month="2026-10", key_daily=None, key_monthly=None, base_day=0, base_month=0)
    authority.call("dispatch", id=identity)
    authority.call("settle", id=identity, cost=None)
    with app.test_request_context():
        hold = admission.reserve(0.0001, scoped_id=identity, context=context)
        admission.mark_dispatched(hold)
        admission.complete(hold, {})
    with app.app_context():
        reservations.reconcile(None, identity, 2, None, admin=True, reason="review",
                               evidence="provider-check", transition_id="a" * 32)
        assert ledger.read(admission.owner(context))["held_microusd"] == 100
        values = dict(admin=True, reason="review", evidence="provider-check", transition_id="b" * 32)
        with patch.object(admission, "reconcile_reservation", side_effect=admission.CreditAdmissionError()):
            with pytest.raises(admission.CreditAdmissionError):
                reservations.reconcile(None, identity, 3, 0.000025, **values)
        for _ in range(2):
            result = reservations.reconcile(None, identity, 3, 0.000025, **values)
            assert result["applied"] is False
    balance = ledger.read(admission.owner(context))
    assert balance["balance_microusd"] == 975 and balance["held_microusd"] == 0
    assert len([entry for entry in balance["entries"] if entry["kind"] == "commit"]) == 1
    totals = authority.call("usage", context=governance.context_dict(context), role="admin")
    assert totals["spent_micro_usd"] == 25 and totals["holds_micro_usd"] == 0


def test_subrequest_flags_off_preserve_legacy_budget_storage_calls(monkeypatch):
    from flask import Response
    from services import accounted_dispatch as dispatch, request_accounting as accounting
    from services.budget_service import BudgetDecision, BudgetService
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "true")
    app = Flask(__name__)
    with app.test_request_context("/v1/chat/completions", method="POST", json=body()):
        g.authenticated_user = {"username": "alice", "daily_budget_usd": 1}
        with patch.object(accounting, "estimate_cost", return_value=0.002) as estimate, \
                patch.object(accounting, "reservation_price", side_effect=AssertionError("legacy pricing changed")), \
                patch.object(BudgetService, "check_and_reserve", return_value=BudgetDecision(True, reservation="legacy")) as reserve, \
                patch.object(accounting, "_record") as record, \
                patch.object(accounting.credits_admission, "reserve", side_effect=AssertionError("disabled credits storage")), \
                patch.object(accounting.tenant_governance, "store", side_effect=AssertionError("disabled governance storage")):
            response = dispatch.accounted_dispatch(body(), lambda _: Response("{}", mimetype="application/json"), kind="chat", skip_rate=True)
            assert response.status_code == 200
            estimate.assert_called_once()
            reserve.assert_called_once_with(g.authenticated_user, 0.002)
            assert record.call_args.args[0].reservation == "legacy"


def test_subrequest_predispatch_refusal_releases_credits_and_governance(credits, tmp_path, monkeypatch):
    from error_handlers import APIError
    from services import accounted_dispatch as dispatch, tenant_governance as governance
    app, ledger, admission, contracts = credits
    context = contracts.TenantContext("alice", "org")
    path = tmp_path / "governance.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript(Path("intelligence-migrations/0034_tenant_governance.sql").read_text())
    authority = governance.SQLiteGovernanceStore(lambda: sqlite3.connect(path))
    governance.register_governance_collaborators(app=app, store=authority, tenant_resolver=lambda _: context)
    monkeypatch.setenv("TENANT_GOVERNANCE_ENABLED", "true")
    fund(ledger, admission.owner(context), 1000)
    def refuse(_):
        raise APIError("before dispatch", 503)
    with app.test_request_context("/v1/chat/completions", method="POST", json=body()):
        g.authenticated_user = {"username": "alice"}
        g.tenant_context = context
        with pytest.raises(APIError):
            dispatch.accounted_dispatch(body(), refuse, kind="chat", skip_rate=True)
    balance = ledger.read(admission.owner(context))
    assert balance["held_microusd"] == 0 and balance["balance_microusd"] == 1000
    assert authority.call("usage", context=governance.context_dict(context), role="admin")["holds_micro_usd"] == 0
