"""Durable dollar holds and accounting preserve uncertain observations."""
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from flask import Flask, g

from services import budget_service, request_accounting as accounting, usage_ledger
from services import reservation_store as reservations

MIGRATION = "0020_usage_reservations.sql"
NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)
USER = {"username": "alice", "daily_budget_usd": 1.0, "monthly_budget_usd": 5.0}


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", "true")
    monkeypatch.setenv("USAGE_HOLD_REVIEW_AFTER_SECONDS", "259200")
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "false")
    monkeypatch.setenv("INTELLIGENCE_STORAGE_BACKEND", "")
    monkeypatch.setenv("CONTROL_PLANE_DATABASE_URL", "")
    monkeypatch.setenv("PROMPT_CACHE_USAGE_BUCKETS_ENABLED", "false")
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", json.dumps({"priced": {"input": 1000, "output": 1000}}))
    instance = reservations.SqlReservationStore(tmp_path / "usage.sqlite3")
    monkeypatch.setattr(reservations, "_store", instance)
    monkeypatch.setattr(usage_ledger.LEDGER, "record", lambda row: None)
    monkeypatch.setattr(accounting.telemetry_export.EXPORTER, "submit", lambda row: None)
    budget_service.BudgetService.reset()
    yield instance
    budget_service.BudgetService.reset()


def reserve(store, identity="a" * 32, estimate=0.6):
    return store.reserve(identity, USER["username"], estimate, 1.0, 5.0, 0.0, 0.0, NOW)


def move(store, row, state, **fields):
    return store.transition(row["id"], row["revision"], state, transition_id=fields.pop("transition_id", "b" * 32),
                            now=NOW, **fields)["reservation"]


def test_disconnect_keeps_hold_across_restart_and_review(store):
    row = reserve(store)
    row = move(store, row, "dispatched", transition_id="c" * 32)
    row = move(store, row, "unknown", input_tokens=0)
    reopened = reservations.SqlReservationStore(store.path)
    status = reopened.summary("alice", NOW + timedelta(days=40), 259200)
    assert status["held_usd"] == 0.6 and status["needs_review"] == 1
    assert reopened.get(row["id"])["output_tokens"] is None
    assert reopened.get(row["id"])["input_tokens"] == 0
    with pytest.raises(reservations.ReservationError, match="budget_exceeded"):
        reserve(reopened, "d" * 32, 0.5)


def test_before_dispatch_release_and_terminal_exactly_once(store):
    row = move(store, reserve(store), "settled", cost_usd=0, basis="released", settlement_id="e" * 32)
    assert store.summary("alice", NOW)["held_usd"] == 0
    with pytest.raises(reservations.ReservationError, match="reservation_conflict"):
        move(store, row, "dispatched", transition_id="f" * 32)


def test_measured_settlement_is_idempotent_and_not_double_charged(store):
    row = move(store, reserve(store), "dispatched", transition_id="c" * 32)
    values = dict(transition_id="d" * 32, settlement_id="e" * 32, cost_usd=0.2, basis="provider",
                  input_tokens=100, output_tokens=100, now=NOW)
    first = store.transition(row["id"], 1, "settled", **values)
    assert first["applied"]
    assert not store.transition(row["id"], 1, "settled", **values)["applied"]
    with pytest.raises(reservations.ReservationError, match="reservation_conflict"):
        store.transition(row["id"], 1, "settled", **{**values, "cost_usd": 0.1})
    summary = store.summary("alice", NOW)
    assert summary["spent_today_usd"] == 0.2 and summary["held_usd"] == 0
    assert len(store.audit(row["id"])) == 3


def test_reconcile_requires_evidence_admin_reason_and_cas(store):
    row = move(store, reserve(store), "dispatched", transition_id="c" * 32)
    row = move(store, row, "unknown")
    with pytest.raises(reservations.ReservationError, match="admin_required"):
        reservations.reconcile(store, row["id"], 2, 0.2, admin=False, evidence="receipt_1", reason="provider_receipt")
    with pytest.raises(reservations.ReservationError, match="reconciliation_evidence_required"):
        reservations.reconcile(store, row["id"], 2, 0.2, admin=True, reason="provider_receipt")
    def claim(index):
        try:
            return reservations.reconcile(store, row["id"], 2, 0.2, admin=True, evidence="receipt_1",
                                          reason="provider_receipt", transition_id=f"{index:032x}")["applied"]
        except reservations.ReservationError as error:
            assert error.code == "reservation_conflict"
            return False
    with ThreadPoolExecutor(max_workers=4) as executor:
        assert sum(executor.map(claim, range(10, 18))) == 1
    assert store.summary("alice", NOW)["spent_today_usd"] == 0.2


def test_authorized_adjustment_retains_audit_and_unknown_tokens(store):
    row = move(store, reserve(store), "dispatched", transition_id="c" * 32)
    row = move(store, row, "unknown", input_tokens=0)
    result = reservations.reconcile(store, row["id"], 2, 0.1, admin=True, authorized_adjustment=True,
                                    reason="approved_adjustment")
    assert result["reservation"]["state"] == "reconciled"
    assert result["reservation"]["input_tokens"] == 0
    assert result["reservation"]["output_tokens"] is None
    assert store.audit(row["id"])[-1]["basis"] == "adjustment"


def test_concurrent_reserves_enforce_shared_budget(store):
    def admit(index):
        try:
            reserve(store, f"{index:032x}", 0.4)
            return True
        except reservations.ReservationError as error:
            assert error.code == "budget_exceeded"
            return False
    with ThreadPoolExecutor(max_workers=6) as executor:
        assert sum(executor.map(admit, range(1, 15))) == 2


def test_budget_admission_and_status_use_durable_authority(store):
    service = budget_service.BudgetService
    first = service.check_and_reserve(USER, 0.6, NOW)
    assert first.allowed
    service.mark_dispatched(first.reservation)
    service.complete(first.reservation, {"cost_usd": None, "cost_basis": None, "input_tokens": 0, "output_tokens": None})
    service.settle(first.reservation)
    service.reset()
    status = service.status(USER, NOW)
    assert status["in_flight_usd"] == 0.6 and status["reservations"]["unknown"] == 1
    assert not service.check_and_reserve(USER, 0.5, NOW).allowed
    refused = service.check_and_reserve(USER, None, NOW)
    assert refused.status_code == 503 and refused.error == "unpriced_reservation"
    assert service.check_and_reserve({"username": "unlimited"}, None, NOW).allowed


def test_legacy_baseline_is_saved_once_and_new_measured_cost_is_counted_once(store, monkeypatch):
    service = budget_service.BudgetService
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "true")
    class Totals:
        def totals(self, *args):
            return {"day_usd": 0.3, "month_usd": 0.5}
    monkeypatch.setattr(usage_ledger.LEDGER, "store", Totals)
    first = service.check_and_reserve(USER, 0.6, NOW)
    service.complete(first.reservation, {"cost_usd": 0.2, "cost_basis": "usage", "input_tokens": 100, "output_tokens": 100})
    service.reset()
    assert service.status(USER, NOW)["spent_today_usd"] == 0.5
    assert service.check_and_reserve(USER, 0.5, NOW).allowed


@pytest.mark.parametrize("flag", ["", "false", "malformed-value"])
def test_disabled_never_touches_storage_or_changes_legacy_status(store, monkeypatch, flag):
    monkeypatch.setenv("USAGE_RESERVATIONS_ENABLED", flag)
    monkeypatch.setattr(reservations, "get_store", lambda: pytest.fail("disabled storage access"))
    service = budget_service.BudgetService
    first = service.check_and_reserve(USER, 0.2, NOW)
    service.settle(first.reservation)
    assert "reservations" not in service.status(USER, NOW)


@pytest.mark.parametrize("value,enabled", [("", True), ("bad", False), ("0", False), ("-1", False)])
def test_review_config_is_default_or_fail_safe(store, monkeypatch, value, enabled):
    monkeypatch.setenv("USAGE_HOLD_REVIEW_AFTER_SECONDS", value)
    assert reservations.enabled() is enabled


def test_missing_schema_fails_closed_and_additive_migration_keeps_old_rows(store, monkeypatch, tmp_path):
    missing = reservations.SqlReservationStore(tmp_path / "missing.sqlite3", initialize=False)
    monkeypatch.setattr(reservations, "_store", missing)
    decision = budget_service.BudgetService.check_and_reserve(USER, 0.2, NOW)
    assert decision.status_code == 503 and decision.error == "usage_reservations_unavailable"
    with sqlite3.connect(store.path) as db:
        db.execute("CREATE TABLE old_rows (value TEXT)")
        db.execute("INSERT INTO old_rows VALUES ('keep')")
        db.executescript((Path(__file__).parents[1] / "intelligence-migrations" / MIGRATION).read_text())
        assert db.execute("SELECT value FROM old_rows").fetchone()[0] == "keep"


def test_accounting_unknown_is_not_converted_to_zero_or_an_estimate(store):
    app = Flask(__name__)
    with app.test_request_context("/v1/chat/completions", method="POST", json={"model": "priced", "messages": [], "max_tokens": 100}):
        g.authenticated_user = USER
        assert accounting.begin() is None
        ctx = g.usage_context
        observer = accounting.cancellation_observer()
        from services.request_cancellation import CancellationContext
        owner = CancellationContext(lambda: None, on_outcome=observer)
        owner.handoff()
        owner.cancel()
        rows = []
        with patch.object(usage_ledger.LEDGER, "record", rows.append):
            accounting.finish(app.response_class(b"unchanged", status=200))
        row = store.get(ctx.reservation)
        assert row["state"] == "unknown" and row["cost_usd"] is None
        assert row["input_tokens"] is None and row["output_tokens"] is None
        assert rows[0]["cost_usd"] is None


def test_registered_accounting_boundary_preserves_body_and_unpriced_fails_before_view(store):
    app = Flask(__name__)
    calls = []
    @app.post("/v1/chat/completions")
    def chat():
        g.authenticated_user = USER
        refused = accounting.begin()
        if refused is not None:
            return refused
        calls.append(True)
        return accounting.finish(app.response_class(b'{"usage":{"input_tokens":10,"output_tokens":20}}', mimetype="application/json"))
    client = app.test_client()
    response = client.post("/v1/chat/completions", json={"model": "priced", "max_tokens": 100})
    assert response.data == b'{"usage":{"input_tokens":10,"output_tokens":20}}'
    assert budget_service.BudgetService.status(USER)["spent_today_usd"] == 0.03
    response = client.post("/v1/chat/completions", json={"model": "unpriced"})
    assert response.status_code == 503 and response.json["error"] == "unpriced_reservation"
    assert len(calls) == 1


def test_failed_finalization_retains_reservation_and_cached_completion_releases_before_handoff(store, monkeypatch):
    service = budget_service.BudgetService
    first = service.check_and_reserve(USER, 0.5, NOW)
    service.complete(first.reservation, {"cost_usd": 0, "cost_basis": "cache"}, cached=True)
    assert store.get(first.reservation)["basis"] == "released"
    second = service.check_and_reserve(USER, 0.5, NOW)
    monkeypatch.setattr(store, "transition", lambda *args, **kw: (_ for _ in ()).throw(reservations.ReservationError()))
    with pytest.raises(reservations.ReservationError):
        service.complete(second.reservation, {"cost_usd": 0.2, "cost_basis": "usage"})
    service.settle(second.reservation)
    assert store.get(second.reservation)["state"] == "reserved"
    assert service.status(USER, NOW)["in_flight_usd"] == 0.5


def test_estimated_success_keeps_unknown_cost_and_admission_period_in_ledger(store, monkeypatch):
    ctx = accounting.UsageContext("chat", ["priced"], None, USER, 0, 0, input_tokens=10, output_tokens=20)
    ctx.path = "/v1/chat/completions"
    ctx.reservation = budget_service.BudgetService.check_and_reserve(USER, 0.03, NOW).reservation
    rows = []
    monkeypatch.setattr(usage_ledger.LEDGER, "record", rows.append)
    accounting._record(ctx, 200, None, None)
    assert rows[0]["at"] == "2026-10-09T00:00:00.000Z"
    assert rows[0]["cost_usd"] is None and rows[0]["cost_basis"] is None
    assert store.get(ctx.reservation)["state"] == "unknown"


def test_pricing_refuses_any_unpriced_auto_candidate(store, monkeypatch):
    monkeypatch.setattr(accounting, "_candidates", lambda model: ["priced", "unpriced"])
    assert accounting.reservation_price(["auto:chat"], 10, 20, 1) is None


def test_period_rollover_preserves_unknown_hold_and_settles_original_period(store):
    row = reserve(store)
    row = move(store, row, "dispatched", transition_id="c" * 32)
    later = NOW + timedelta(days=31)
    assert store.summary("alice", later)["held_usd"] == 0.6
    store.transition(row["id"], 1, "settled", transition_id="f" * 32, settlement_id="e" * 32,
                     cost_usd=0.2, basis="provider", now=later)
    assert store.summary("alice", later)["spent_this_month_usd"] == 0
    assert store.summary("alice", NOW)["spent_this_month_usd"] == 0.2


def test_identifiers_monetary_limits_and_settlement_claims_are_bounded(store):
    for estimate in [-1, float("nan"), float("inf"), True, "1"]:
        with pytest.raises(reservations.ReservationError, match="invalid_reservation_request"):
            reserve(store, estimate=estimate)
    first = move(store, reserve(store, estimate=0.3), "dispatched", transition_id="c" * 32)
    first = move(store, first, "settled", transition_id="f" * 32, settlement_id="e" * 32,
                 cost_usd=0.2, basis="provider")
    second = reserve(store, "1" * 32, 0.3)
    second = move(store, second, "dispatched", transition_id="2" * 32)
    with pytest.raises(reservations.ReservationError, match="reservation_conflict"):
        move(store, second, "settled", transition_id="3" * 32, settlement_id="e" * 32, cost_usd=0.2, basis="provider")
    assert store.get(second["id"])["state"] == "dispatched"


from tests.unified_api_test_case import UnifiedApiTestCase


class DurableUsageRoutesTest(UnifiedApiTestCase):
    def setUp(self):
        self.env_patch = patch("config.load_runtime_env")
        self.http_patch = patch("requests.sessions.Session.request", side_effect=AssertionError("unexpected HTTP"))
        self.env_patch.start()
        self.http_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.addCleanup(self.http_patch.stop)
        super().setUp()
        import os
        os.environ.update({"USAGE_RESERVATIONS_ENABLED": "true", "USAGE_HOLD_REVIEW_AFTER_SECONDS": "259200",
            "USAGE_LEDGER_ENABLED": "false", "INTELLIGENCE_STORAGE_BACKEND": "", "CONTROL_PLANE_DATABASE_URL": "",
            "PROMPT_CACHE_USAGE_BUCKETS_ENABLED": "false", "USAGE_DB_PATH": str(Path(self.temp_dir.name) / "usage.sqlite3"),
            "MODEL_PRICING_USD_PER_MILLION": json.dumps({"opencode:*": {"input": 1000, "output": 1000}})})
        self.store = accounting.reservation_store.SqlReservationStore()
        self.store_patch = patch.object(accounting.reservation_store, "_store", self.store)
        self.store_patch.start()
        self.addCleanup(self.store_patch.stop)
        accounting.BudgetService.reset()
        self.addCleanup(accounting.BudgetService.reset)
        self.rows = []
        self.ledger_patch = patch.object(accounting.usage_ledger.LEDGER, "record", self.rows.append)
        self.ledger_patch.start()
        self.addCleanup(self.ledger_patch.stop)
        with patch.object(self.app_module.AuthService, "get_current_user", return_value={"username": "admin", "is_admin": True}):
            self.key = self.app_module.AuthService.create_user("bounded", scopes=["chat", "models"])["api_key"]
            self.app_module.AuthService.set_key_controls("bounded", {"daily_budget_usd": 1.0, "monthly_budget_usd": 5.0})
        self.headers = {"Authorization": f"Bearer {self.key}"}

    def test_real_chat_and_usage_paths_show_durable_settlement_without_body_changes(self):
        upstream = self._chat_response("ok")
        upstream._content = b'{"choices":[],"usage":{"input_tokens":10,"output_tokens":20}}'
        with patch.object(self.app_module.ProxyService, "make_request", return_value=upstream):
            response = self.client.post("/v1/chat/completions", headers=self.headers,
                json={"model": "opencode:test", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 100})
        assert response.status_code == 200 and response.data == upstream.content
        status = self.client.get("/v1/usage", headers=self.headers)
        assert status.status_code == 200
        assert status.json["budget"]["spent_today_usd"] == 0.03
        assert status.json["budget"]["reservations"]["held_usd"] == 0

    def test_missing_durable_table_refuses_chat_before_upstream(self):
        missing = reservations.SqlReservationStore(Path(self.temp_dir.name) / "missing.sqlite3", initialize=False)
        with patch.object(accounting.reservation_store, "_store", missing), patch.object(self.app_module.ProxyService, "make_request") as upstream:
            response = self.client.post("/v1/chat/completions", headers=self.headers,
                json={"model": "opencode:test", "messages": [], "max_tokens": 100})
        assert response.status_code == 503 and response.json["error"] == "usage_reservations_unavailable"
        upstream.assert_not_called()


def test_malformed_private_transport_response_and_bounded_error_fail_closed(store):
    for body in [{"version": 1}, {"version": 1, "reservation": {}}, {"version": 1, "summary": {}}]:
        remote = reservations.D1ReservationStore(lambda request: body)
        with pytest.raises(reservations.ReservationError):
            remote.get("a" * 32)
    class RemoteError(Exception):
        code = "budget_exceeded"
    def unavailable(request):
        raise RemoteError()
    with pytest.raises(reservations.ReservationError) as failure:
        reservations.D1ReservationStore(unavailable).get("a" * 32)
    assert failure.value.status == 429 and failure.value.code == "budget_exceeded"


def test_extremely_long_review_setting_disables_without_exposing_value(store, monkeypatch, caplog):
    reservations._warned.clear()
    value = "9" * 5000
    monkeypatch.setenv("USAGE_HOLD_REVIEW_AFTER_SECONDS", value)
    assert not reservations.enabled() and not reservations.enabled()
    assert value not in caplog.text
    assert sum("USAGE_HOLD_REVIEW_AFTER_SECONDS" in message for message in caplog.messages) == 1


def test_fractional_budget_does_not_round_up_a_hold_above_the_configured_limit(store):
    with pytest.raises(reservations.ReservationError, match="budget_exceeded"):
        store.reserve("a" * 32, "alice", 0.00000000001, 0.00000000001, None, 0, 0, NOW)
    assert store.summary("alice", NOW)["held_usd"] == 0
