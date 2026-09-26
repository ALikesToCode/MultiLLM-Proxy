"""Per-key dollar budgets: durable totals, local spend, in-flight estimates and periods."""

from datetime import datetime, timezone

import pytest

from services import budget_service, usage_ledger
from services.budget_service import BudgetService

NOW = datetime(2026, 9, 26, 22, 0, tzinfo=timezone.utc)
AT = "2026-09-26T21:59:00.000Z"


class Totals:
    backend = "sql"

    def __init__(self, day=0.0, month=0.0):
        self.day, self.month, self.calls, self.fail = day, month, 0, False

    def totals(self, principal, day, month_start):
        self.calls += 1
        if self.fail:
            raise RuntimeError("storage unavailable")
        assert (day, month_start) == ("2026-09-26", "2026-09-01")
        return {"day_usd": self.day, "month_usd": self.month, "day_requests": 0, "month_requests": 0}


@pytest.fixture
def totals(monkeypatch):
    monkeypatch.setenv("USAGE_LEDGER_ENABLED", "true")
    store = Totals()
    monkeypatch.setattr(usage_ledger.LEDGER, "store", lambda: store)
    BudgetService.reset()
    yield store
    BudgetService.reset()


def user(daily=None, monthly=None, **extra):
    return {"username": "alice", "daily_budget_usd": daily, "monthly_budget_usd": monthly, **extra}


def spend(cost, principal="alice", at=AT):
    row = {"principal": principal, "at": at, "cost_usd": cost}
    BudgetService.record_cost(row)
    return row


def test_keys_without_budgets_and_admins_without_one_are_not_checked(totals):
    assert BudgetService.check_and_reserve(user(), 100.0, NOW).allowed
    assert BudgetService.check_and_reserve(user(is_admin=True), 100.0, NOW).allowed
    assert totals.calls == 0
    assert not BudgetService.check_and_reserve(user(daily=1.0, is_admin=True), 2.0, NOW).allowed


def test_durable_totals_local_spend_and_in_flight_estimates_all_count(totals):
    totals.day, totals.month = 0.5, 4.0
    first = BudgetService.check_and_reserve(user(daily=1.0), 0.3, NOW)
    assert first.allowed and first.reservation
    second = BudgetService.check_and_reserve(user(daily=1.0), 0.3, NOW)
    assert not second.allowed, "0.5 stored + 0.3 in flight + 0.3 exceeds 1.0"
    assert second.status_code == 429 and second.error == "budget_exceeded"
    assert second.retry_after == 2 * 3600 + 1
    assert second.details["period"] == "daily" and second.details["resets_at"] == "2026-09-27T00:00:00+00:00"
    BudgetService.settle(first.reservation)
    spend(0.3)
    assert not BudgetService.check_and_reserve(user(daily=1.0), 0.25, NOW).allowed, "0.8 spent + 0.25 > 1.0"
    decision = BudgetService.check_and_reserve(user(daily=1.0), 0.15, NOW)
    assert decision.allowed
    BudgetService.settle(decision.reservation)
    assert totals.calls == 1, "durable totals are read at most once per refresh interval"


def test_monthly_limits_reset_on_the_first_of_the_next_month(totals):
    totals.month = 9.99
    decision = BudgetService.check_and_reserve(user(daily=5.0, monthly=10.0), 0.02, NOW)
    assert not decision.allowed and decision.details["period"] == "monthly"
    assert decision.details["resets_at"] == "2026-10-01T00:00:00+00:00"
    assert "$10.00" in decision.message


def test_a_zero_budget_freezes_the_key_even_for_unpriced_requests(totals):
    assert not BudgetService.check_and_reserve(user(daily=0.0), 0.0, NOW).allowed


def test_stored_rows_are_not_counted_twice_after_a_refresh(totals, monkeypatch):
    monkeypatch.setenv("USAGE_BUDGET_REFRESH_SECONDS", "3600")
    BudgetService.on_flushed([spend(0.4)])
    totals.day = totals.month = 0.4
    assert BudgetService.status(user(daily=1.0), NOW)["spent_today_usd"] == pytest.approx(0.4)
    # Stored after the read: counted locally until the next read includes it.
    BudgetService.on_flushed([spend(0.1)])
    pending = spend(0.05)
    assert BudgetService.status(user(daily=1.0), NOW)["spent_today_usd"] == pytest.approx(0.55)
    totals.day = totals.month = 0.5
    monkeypatch.setattr(budget_service, "_refresh_seconds", lambda: 0.0)
    status = BudgetService.status(user(daily=1.0), NOW)
    assert status["spent_today_usd"] == pytest.approx(0.55), "stored rows leave the local count, pending rows stay"
    assert status["daily_remaining_usd"] == pytest.approx(0.45)
    BudgetService.on_flushed([pending])
    totals.day = totals.month = 0.55
    assert BudgetService.status(user(daily=1.0), NOW)["spent_today_usd"] == pytest.approx(0.55)


def test_rows_the_ledger_never_stores_still_count(totals, monkeypatch):
    monkeypatch.setattr(budget_service, "_refresh_seconds", lambda: 0.0)
    row = spend(0.7)
    BudgetService.on_dropped([row])
    assert BudgetService.status(user(daily=1.0), NOW)["spent_today_usd"] == pytest.approx(0.7)
    assert not BudgetService.check_and_reserve(user(daily=1.0), 0.5, NOW).allowed


def test_unavailable_totals_fail_closed_until_first_read_then_use_the_last_copy(totals, monkeypatch):
    totals.fail = True
    decision = BudgetService.check_and_reserve(user(daily=1.0), 0.1, NOW)
    assert not decision.allowed and decision.status_code == 503 and decision.error == "budget_unavailable"
    assert BudgetService.status(user(daily=1.0), NOW)["totals_available"] is False
    totals.fail = False
    monkeypatch.setattr(budget_service, "FAILURE_RETRY_SECONDS", 0.0)
    BudgetService._principals["alice"].failed_until = 0.0
    assert BudgetService.check_and_reserve(user(daily=1.0), 0.1, NOW).allowed
    totals.fail = True
    monkeypatch.setattr(budget_service, "_refresh_seconds", lambda: 0.0)
    assert BudgetService.check_and_reserve(user(daily=1.0), 0.1, NOW).allowed, "a stale copy beats refusing"


def test_status_reports_spend_and_remaining_budget(totals):
    totals.day, totals.month = 0.25, 2.0
    status = BudgetService.status(user(daily=1.0), NOW)
    assert status["daily_remaining_usd"] == 0.75 and status["monthly_remaining_usd"] is None
    assert status["spent_this_month_usd"] == 2.0 and status["daily_resets_at"].startswith("2026-09-27")
