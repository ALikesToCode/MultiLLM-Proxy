"""Atomic, content-free dollar reservations; uncertain handoffs never expire money."""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR
from pathlib import Path
from typing import Any

from services.sqlite_store import storage_path

logger = logging.getLogger(__name__)
SCALE = 10_000_000_000
MAX_UNITS = 2**53 - 1
DEFAULT_REVIEW_SECONDS = 259200
ACTIVE = ("reserved", "dispatched", "unknown")
MIGRATION = "0020_usage_reservations.sql"
_ID = re.compile(r"[0-9a-f]{32}\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_warned: set[str] = set()
_warn_lock = threading.Lock()
_store: Any = None


class ReservationError(Exception):
    def __init__(self, code="usage_reservations_unavailable", status=503):
        super().__init__(code)
        self.code, self.status = code, status


def _warn(name):
    with _warn_lock:
        if name not in _warned:
            _warned.add(name)
            logger.warning("Invalid %s; usage reservations disabled", name)


def review_seconds() -> int | None:
    raw = os.environ.get("USAGE_HOLD_REVIEW_AFTER_SECONDS", "").strip()
    if not raw:
        return DEFAULT_REVIEW_SECONDS
    if len(raw) > 10 or not raw.isascii() or not raw.isdecimal() or not 1 <= int(raw) <= 2**31 - 1:
        _warn("USAGE_HOLD_REVIEW_AFTER_SECONDS")
        return None
    return int(raw)


def enabled() -> bool:
    raw = os.environ.get("USAGE_RESERVATIONS_ENABLED", "").strip().lower()
    if raw in {"", "false", "0", "no", "off"}:
        return False
    if raw not in {"true", "1", "yes", "on"}:
        _warn("USAGE_RESERVATIONS_ENABLED")
        return False
    return review_seconds() is not None


def units(value, *, limit=False) -> int:
    if type(value) not in (int, float):
        raise ReservationError("invalid_reservation_request", 400)
    try:
        amount = Decimal(str(value)) * SCALE
        if not amount.is_finite() or not 0 <= amount <= MAX_UNITS:
            raise ValueError()
        return int(amount.to_integral_value(rounding=ROUND_FLOOR if limit else ROUND_CEILING))
    except (InvalidOperation, ValueError, OverflowError):
        raise ReservationError("invalid_reservation_request", 400) from None


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ReservationError("invalid_reservation_request", 400)
    return value


def _principal(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ReservationError("invalid_reservation_request", 400)
    return value


def clock(now=None):
    value = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return int(value.timestamp() * 1000), value.strftime("%Y-%m-%d"), value.strftime("%Y-%m")


def public(row):
    value = dict(row)
    value["estimate_usd"] = value.pop("amount_units") / SCALE
    charged = value.pop("charged_units")
    value["cost_usd"] = charged / SCALE if charged is not None else None
    return value


def _document(fields):
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def transition_fields(state, *, cost_usd=None, basis=None, input_tokens=None, output_tokens=None,
                      settlement_id=None, admin=False, evidence=None, authorized_adjustment=False, reason=None):
    if state not in {"dispatched", "unknown", "settled", "reconciled"}:
        raise ReservationError("invalid_reservation_request", 400)
    for value in (input_tokens, output_tokens):
        if value is not None and (type(value) is not int or not 0 <= value <= MAX_UNITS):
            raise ReservationError("invalid_reservation_request", 400)
    charged = None if cost_usd is None else units(cost_usd)
    if state in {"settled", "reconciled"}:
        _identifier(settlement_id)
        if charged is None or basis not in {"provider", "released", "adjustment"}:
            raise ReservationError("invalid_reservation_request", 400)
    elif any(value is not None for value in (cost_usd, basis, settlement_id, evidence, reason)):
        raise ReservationError("invalid_reservation_request", 400)
    if state == "settled" and (basis == "adjustment" or (basis == "released" and charged != 0)):
        raise ReservationError("invalid_reservation_request", 400)
    if state == "reconciled":
        if admin is not True:
            raise ReservationError("admin_required", 403)
        if not isinstance(reason, str) or not _LABEL.fullmatch(reason):
            raise ReservationError("reconciliation_evidence_required", 400)
        if basis == "provider":
            if not isinstance(evidence, str) or not _LABEL.fullmatch(evidence):
                raise ReservationError("reconciliation_evidence_required", 400)
        elif basis != "adjustment" or authorized_adjustment is not True or evidence is not None:
            raise ReservationError("reconciliation_evidence_required", 400)
    elif evidence is not None or reason is not None or admin or authorized_adjustment:
        raise ReservationError("invalid_reservation_request", 400)
    return dict(charged_units=charged, basis=basis, input_tokens=input_tokens, output_tokens=output_tokens,
                settlement_id=settlement_id, evidence=evidence, reason=reason)


def reconcile(store, identity, revision, cost_usd, *, admin, reason, evidence=None,
              authorized_adjustment=False, transition_id=None):
    return store.transition(identity, revision, "reconciled", cost_usd=cost_usd,
                            admin=admin, reason=reason, evidence=evidence,
                            authorized_adjustment=authorized_adjustment,
                            basis="adjustment" if authorized_adjustment else "provider",
                            transition_id=transition_id or uuid.uuid4().hex, settlement_id=identity)


class SqlReservationStore:
    """SQLite authority; BEGIN IMMEDIATE serializes admission and terminal claims."""
    def __init__(self, path=None, *, initialize=True):
        self.path = Path(path) if path is not None else storage_path("USAGE_DB_PATH", "usage.sqlite3")
        if initialize:
            try:
                with closing(self._connect()) as db:
                    db.executescript((Path(__file__).resolve().parents[1] / "intelligence-migrations" / MIGRATION).read_text())
            except (sqlite3.Error, OSError):
                raise ReservationError() from None

    def _connect(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        existed = self.path.exists()
        db = sqlite3.connect(self.path, timeout=10)
        if not existed:
            self.path.chmod(0o600)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def _run(self, operation):
        try:
            with closing(self._connect()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                return operation(db)
        except (sqlite3.Error, OSError):
            raise ReservationError() from None

    def get(self, identity):
        _identifier(identity)
        def read(db):
            row = db.execute("SELECT * FROM usage_reservations WHERE id = ?", (identity,)).fetchone()
            if row is None:
                raise ReservationError("reservation_not_found", 404)
            return public(row)
        return self._run(read)

    def audit(self, identity):
        _identifier(identity)
        return self._run(lambda db: [dict(row) for row in db.execute(
            "SELECT * FROM usage_reservation_transitions WHERE reservation_id = ? ORDER BY rowid", (identity,))])

    def reserve(self, identity, principal, estimate_usd, daily_budget_usd, monthly_budget_usd,
                day_spent_usd, month_spent_usd, now=None):
        _identifier(identity)
        _principal(principal)
        if daily_budget_usd is None and monthly_budget_usd is None:
            raise ReservationError("invalid_reservation_request", 400)
        if estimate_usd is None:
            raise ReservationError("unpriced_reservation", 503)
        amount = units(estimate_usd)
        daily = None if daily_budget_usd is None else units(daily_budget_usd, limit=True)
        monthly = None if monthly_budget_usd is None else units(monthly_budget_usd, limit=True)
        baseline = (units(day_spent_usd), units(month_spent_usd))
        at, day, month = clock(now)
        document = _document(dict(id=identity, principal=principal, amount_units=amount, day=day, month=month))
        def write(db):
            existing = db.execute("SELECT * FROM usage_reservations WHERE id = ?", (identity,)).fetchone()
            if existing is not None:
                audit = db.execute("SELECT document FROM usage_reservation_transitions WHERE transition_id = ?", (identity,)).fetchone()
                if existing["state"] != "reserved" or not audit or audit[0] != document:
                    raise ReservationError("reservation_conflict", 409)
                return public(existing)
            if db.execute("SELECT 1 FROM usage_reservation_transitions WHERE transition_id = ?", (identity,)).fetchone():
                raise ReservationError("reservation_conflict", 409)
            for period, spent in zip((day, month), baseline):
                db.execute("INSERT OR IGNORE INTO usage_reservation_budgets VALUES (?, ?, ?)", (principal, period, spent))
            summary = self._summary(db, principal, at, day, month, DEFAULT_REVIEW_SECONDS)
            for limit, spent in ((daily, summary["day_units"]), (monthly, summary["month_units"])):
                if limit is not None and (spent + summary["held_units"] >= limit
                                          or spent + summary["held_units"] + amount > limit):
                    raise ReservationError("budget_exceeded", 429)
            db.execute("""INSERT INTO usage_reservations
                (id, principal, day, month, amount_units, state, created_at, updated_at, transition_id)
                VALUES (?, ?, ?, ?, ?, 'reserved', ?, ?, ?)""", (identity, principal, day, month, amount, at, at, identity))
            db.execute("""INSERT INTO usage_reservation_transitions
                (transition_id, reservation_id, state, at, document) VALUES (?, ?, 'reserved', ?, ?)""",
                       (identity, identity, at, document))
            return public(db.execute("SELECT * FROM usage_reservations WHERE id = ?", (identity,)).fetchone())
        return self._run(write)

    def transition(self, identity, revision, state, *, transition_id, now=None, **values):
        _identifier(identity)
        _identifier(transition_id)
        if type(revision) is not int or not 0 <= revision <= MAX_UNITS:
            raise ReservationError("invalid_reservation_request", 400)
        fields = transition_fields(state, **values)
        document = _document(dict(id=identity, revision=revision, state=state, **fields))
        at, _, _ = clock(now)
        def write(db):
            row = db.execute("SELECT * FROM usage_reservations WHERE id = ?", (identity,)).fetchone()
            if row is None:
                raise ReservationError("reservation_not_found", 404)
            previous = db.execute("SELECT document FROM usage_reservation_transitions WHERE transition_id = ?", (transition_id,)).fetchone()
            if previous:
                if previous[0] != document:
                    raise ReservationError("reservation_conflict", 409)
                return {"applied": False, "reservation": public(row)}
            legal = ((row["state"] == "reserved" and state == "dispatched")
                     or (row["state"] == "reserved" and state == "settled" and fields["basis"] == "released")
                     or (row["state"] == "dispatched" and state in {"unknown", "settled"} and fields["basis"] != "released")
                     or (row["state"] == "unknown" and state == "reconciled"))
            if row["revision"] != revision or not legal:
                raise ReservationError("reservation_conflict", 409)
            if fields["settlement_id"] and db.execute("SELECT 1 FROM usage_reservations WHERE settlement_id = ?",
                                                      (fields["settlement_id"],)).fetchone():
                raise ReservationError("reservation_conflict", 409)
            db.execute("""UPDATE usage_reservations SET state = ?, revision = revision + 1,
                charged_units = ?, basis = ?, input_tokens = COALESCE(?, input_tokens),
                output_tokens = COALESCE(?, output_tokens), updated_at = ?,
                handoff_at = CASE WHEN ? = 'dispatched' THEN ? ELSE handoff_at END,
                transition_id = ?, settlement_id = ? WHERE id = ? AND revision = ?""",
                       (state, fields["charged_units"], fields["basis"], fields["input_tokens"], fields["output_tokens"],
                        at, state, at, transition_id, fields["settlement_id"], identity, revision))
            db.execute("""INSERT INTO usage_reservation_transitions
                (transition_id, reservation_id, previous_state, state, at, basis, evidence, reason, document)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (transition_id, identity, row["state"], state, at,
                                                      fields["basis"], fields["evidence"], fields["reason"], document))
            return {"applied": True, "reservation": public(db.execute(
                "SELECT * FROM usage_reservations WHERE id = ?", (identity,)).fetchone())}
        return self._run(write)

    @staticmethod
    def _summary(db, principal, at, day, month, review):
        totals = dict(db.execute("""SELECT
            COALESCE(SUM(CASE WHEN state IN ('reserved','dispatched','unknown') THEN amount_units ELSE 0 END),0) AS held_units,
            COALESCE(SUM(CASE WHEN state IN ('settled','reconciled') AND day = ? THEN charged_units ELSE 0 END),0) AS day_units,
            COALESCE(SUM(CASE WHEN state IN ('settled','reconciled') AND month = ? THEN charged_units ELSE 0 END),0) AS month_units,
            COUNT(CASE WHEN state = 'reserved' THEN 1 END) AS reserved,
            COUNT(CASE WHEN state = 'dispatched' THEN 1 END) AS dispatched,
            COUNT(CASE WHEN state = 'unknown' THEN 1 END) AS unknown,
            COUNT(CASE WHEN state IN ('reserved','dispatched','unknown') AND created_at <= ? THEN 1 END) AS needs_review
            FROM usage_reservations WHERE principal = ?""", (day, month, at - review * 1000, principal)).fetchone())
        for name, period in (("day", day), ("month", month)):
            base = db.execute("SELECT baseline_units FROM usage_reservation_budgets WHERE principal = ? AND period = ?",
                              (principal, period)).fetchone()
            totals[name + "_seeded"] = base is not None
            totals[name + "_units"] += base[0] if base else 0
        return totals

    def summary(self, principal, now=None, review_after=DEFAULT_REVIEW_SECONDS):
        _principal(principal)
        if type(review_after) is not int or not 1 <= review_after <= 2**31 - 1:
            raise ReservationError("invalid_reservation_request", 400)
        at, day, month = clock(now)
        result = self._run(lambda db: self._summary(db, principal, at, day, month, review_after))
        for target, source in (("held_usd", "held_units"), ("spent_today_usd", "day_units"),
                               ("spent_this_month_usd", "month_units")):
            result[target] = result.pop(source) / SCALE
        return result


def _validate_response(operation, result):
    try:
        expected = {"version", "reservation"} if operation in {"get", "reserve"} else {
            "transition": {"version", "reservation", "applied"}, "summary": {"version", "summary"},
            "audit": {"version", "transitions"}}[operation]
        if set(result) != expected:
            raise ReservationError()
        if operation in {"get", "reserve", "transition"}:
            row = result["reservation"]
            fields = {"id", "principal", "day", "month", "estimate_usd", "cost_usd", "state", "basis",
                      "input_tokens", "output_tokens", "created_at", "updated_at", "handoff_at", "revision",
                      "transition_id", "settlement_id"}
            if not isinstance(row, dict) or set(row) != fields:
                raise ReservationError()
            _identifier(row["id"])
            _identifier(row["transition_id"])
            _principal(row["principal"])
            units(row["estimate_usd"])
            if row["cost_usd"] is not None:
                units(row["cost_usd"])
            if row["state"] not in {"reserved", "dispatched", "unknown", "settled", "reconciled"}:
                raise ReservationError()
            if operation == "transition" and type(result["applied"]) is not bool:
                raise ReservationError()
        elif operation == "summary":
            summary = result["summary"]
            fields = {"day_seeded", "month_seeded", "held_usd", "spent_today_usd", "spent_this_month_usd",
                      "reserved", "dispatched", "unknown", "needs_review"}
            if not isinstance(summary, dict) or set(summary) != fields:
                raise ReservationError()
            for field in ("day_seeded", "month_seeded"):
                if type(summary[field]) is not bool:
                    raise ReservationError()
            for field in ("held_usd", "spent_today_usd", "spent_this_month_usd"):
                units(summary[field])
            for field in ("reserved", "dispatched", "unknown", "needs_review"):
                if type(summary[field]) is not int or summary[field] < 0:
                    raise ReservationError()
        elif not isinstance(result["transitions"], list) or len(result["transitions"]) > 100:
            raise ReservationError()
    except (ReservationError, KeyError, TypeError, ValueError):
        raise ReservationError() from None


class D1ReservationStore:
    """Injected private transport; no retry or alternate local authority on failure."""
    def __init__(self, call):
        self.call = call

    def _call(self, operation, **values):
        try:
            result = self.call({"version": 1, "operation": operation, **values})
            if not isinstance(result, dict) or result.get("version") != 1:
                raise ReservationError()
            if "error" in result:
                code = result["error"].get("code")
                statuses = {"budget_exceeded": 429, "reservation_conflict": 409, "admin_required": 403,
                            "reconciliation_evidence_required": 400, "invalid_reservation_request": 400,
                            "reservation_not_found": 404, "unpriced_reservation": 503}
                raise ReservationError(code if code in statuses else "usage_reservations_unavailable", statuses.get(code, 503))
            _validate_response(operation, result)
            return result
        except ReservationError:
            raise
        except Exception as error:
            code = getattr(error, "code", None)
            statuses = {"budget_exceeded": 429, "reservation_conflict": 409, "admin_required": 403,
                        "reconciliation_evidence_required": 400, "invalid_reservation_request": 400,
                        "reservation_not_found": 404, "unpriced_reservation": 503}
            raise ReservationError(code if code in statuses else "usage_reservations_unavailable", statuses.get(code, 503)) from None

    def reserve(self, identity, principal, estimate_usd, daily_budget_usd, monthly_budget_usd,
                day_spent_usd, month_spent_usd, now=None):
        return self._call("reserve", id=identity, principal=principal, estimate_usd=estimate_usd,
                          daily_budget_usd=daily_budget_usd, monthly_budget_usd=monthly_budget_usd,
                          day_spent_usd=day_spent_usd, month_spent_usd=month_spent_usd)["reservation"]

    def get(self, identity):
        return self._call("get", id=identity)["reservation"]

    def transition(self, identity, revision, state, *, transition_id, now=None, **values):
        result = self._call("transition", id=identity, revision=revision, state=state, transition_id=transition_id, **values)
        return {"applied": result["applied"], "reservation": result["reservation"]}

    def summary(self, principal, now=None, review_after=DEFAULT_REVIEW_SECONDS):
        return self._call("summary", principal=principal)["summary"]

    def audit(self, identity):
        return self._call("audit", id=identity)["transitions"]


def configure_store(store):
    global _store
    _store = store


def get_store():
    from services import control_state_d1
    if _store is not None:
        if control_state_d1.using_d1() and not isinstance(_store, D1ReservationStore):
            raise ReservationError()
        return _store
    if control_state_d1.using_d1():
        def call(document):
            values = {key: value for key, value in document.items() if key not in {"version", "operation"}}
            return control_state_d1.call("reservations", document["operation"], **values)
        return D1ReservationStore(call)
    if os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip() != "":
        raise ReservationError()
    return SqlReservationStore()
