"""Revision-bound request credits, separate from key and workspace budgets."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_CEILING
from typing import Any

from flask import current_app, jsonify

from services import credits_ledger
from services.enterprise_contract import AuthorityOperation, TenantContext, call_authority
from services.tenant_hierarchy import current_tenant

_tariff_expectation: ContextVar[tuple | None] = ContextVar("request_credit_tariff", default=None)
REVISION_ATTEMPTS = 3


class CreditAdmissionError(Exception):
    def __init__(self, code="credits_unavailable", status=503):
        super().__init__(code)
        self.code, self.status = code, status


def error_response(error):
    response = jsonify({"error": error.code, "message": "Request credit admission is unavailable."
                        if error.status == 503 else "This request exceeds available credits."})
    response.status_code = error.status
    return response


def enforcement():
    return credits_ledger.enforcement() if credits_ledger.enabled() else "off"


def owner(context=None):
    return credits_ledger.context_owner(context or current_tenant())


def micro_usd(value, *, positive=False):
    try:
        number = Decimal(str(value)) * 1_000_000
        if isinstance(value, bool) or not number.is_finite() or number < 0:
            raise ValueError()
        amount = int(number.to_integral_value(rounding=ROUND_CEILING))
        credits_ledger.integer(amount, nonnegative=True)
        if positive and amount == 0:
            raise ValueError()
        return amount
    except (ValueError, ArithmeticError, credits_ledger.CreditsError):
        raise CreditAdmissionError("credits_unpriced") from None


def tariff_revision():
    """The integer revision of the exact configured gateway price document."""
    raw = os.environ.get("MODEL_PRICING_USD_PER_MILLION", "")
    return int(hashlib.sha256(raw.encode()).hexdigest()[:12], 16)


def _tariff(operation, phase):
    expected = _tariff_expectation.get()
    if expected is None or expected[:3] != (operation.operation_id, phase, operation.amount):
        return None
    return expected[3]


def register_credits_admission(app):
    app.register_error_handler(CreditAdmissionError, error_response)
    if not credits_ledger.enabled():
        return None
    store = credits_ledger.open_store()
    app.extensions["credits_admission_store"] = store
    return credits_ledger.register_credit_authority(store, tariff=_tariff)


def _failure(error):
    code = getattr(error, "code", None)
    return CreditAdmissionError(code, 402 if code == "credits_insufficient" else 503) if code in {
        "credits_insufficient", "credits_unpriced"} else CreditAdmissionError()


def _retry(store, context, scoped_id, operation_id, amount, apply):
    """Only a refused revision permits retry; an uncertain write is never replayed."""
    for attempt in range(REVISION_ATTEMPTS):
        try:
            revision = store.read(owner(context), limit=1)["revision"]
            operation = AuthorityOperation(context, scoped_id, revision, operation_id, amount)
            return apply(operation)
        except Exception as error:
            if getattr(error, "code", None) == "credits_revision_mismatch" and attempt + 1 < REVISION_ATTEMPTS:
                continue
            raise _failure(error) from None


def operation_id(scoped_id, phase, transition_id=None):
    identity = json.dumps([scoped_id, phase, transition_id], separators=(",", ":"))
    return "credits:" + phase + ":" + hashlib.sha256(identity.encode()).hexdigest()


@dataclass
class CreditHold:
    context: TenantContext
    scoped_id: str
    estimate: int
    price_revision: int
    store: Any
    adapters: Any
    dispatched: bool = False
    terminal: bool = False
    unknown: bool = False
    lock: Any = field(default_factory=threading.Lock, repr=False)


def _authority(hold, phase, amount, *, transition_id=None, unknown=False):
    identity = operation_id(hold.scoped_id, phase, transition_id)
    token = _tariff_expectation.set((identity, phase, amount, None if unknown else hold.price_revision))
    try:
        return _retry(hold.store, hold.context, hold.scoped_id, identity, amount,
                      lambda operation: call_authority(hold.adapters, "credit", phase, operation))
    finally:
        _tariff_expectation.reset(token)


def reserve(estimate_usd, *, scoped_id=None, context=None):
    mode = enforcement()
    if mode == "off":
        return None
    context = context or current_tenant()
    try:
        store = current_app.extensions["credits_admission_store"]
        adapters = current_app.extensions["enterprise_adapters"]
        if mode == "funded" and store.read(owner(context), limit=1)["revision"] == 0:
            return None
        hold = CreditHold(context, scoped_id or uuid.uuid4().hex, micro_usd(estimate_usd, positive=True),
                          tariff_revision(), store, adapters)
        _authority(hold, "reserve", hold.estimate)
        return hold
    except CreditAdmissionError:
        raise
    except Exception as error:
        raise _failure(error) from None


def mark_dispatched(hold):
    if hold is not None:
        hold.dispatched = True


def release(hold, *, cancelled=False):
    if hold is None:
        return
    with hold.lock:
        if hold.terminal or (hold.dispatched and not cancelled):
            return
        identity = operation_id(hold.scoped_id, "release")
        _retry(hold.store, hold.context, hold.scoped_id, identity, hold.estimate,
               lambda operation: hold.store.append(owner(hold.context), "release", operation.amount,
                   operation.operation_id, operation.revision, scoped_id=operation.scoped_id))
        hold.terminal = True


def complete(hold, row, *, cached=False, before_dispatch=False, transition_id=None):
    if hold is None:
        return
    if before_dispatch or cached or (not hold.dispatched and row.get("status", 200) >= 400):
        release(hold)
        return
    with hold.lock:
        if hold.terminal:
            return
        measured = row.get("cost_usd") is not None and row.get("cost_basis") == "usage"
        if not measured and hold.unknown:
            return
        _authority(hold, "reconcile" if transition_id or not measured else "commit",
                   micro_usd(row["cost_usd"]) if measured else 0,
                   transition_id=transition_id, unknown=not measured)
        hold.terminal, hold.unknown = measured, not measured


def reconcile_reservation(row, transition_id):
    """Recover the credits attempt from immutable ledger evidence after a restart."""
    if not credits_ledger.enabled():
        return
    try:
        principal = row["principal"]
        if principal.startswith("tenant:"):
            org, team, principal = json.loads(principal[7:])
            context = TenantContext(principal, org, team)
        else:
            context = TenantContext(principal)
        store = current_app.extensions["credits_admission_store"]
        cursor, entries = "0", []
        while True:
            page = store.read(owner(context), cursor=cursor)
            entries.extend(entry for entry in page["entries"] if entry["scoped_id"] == row["id"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        reserve_entry = next((entry for entry in entries if entry["kind"] == "reserve" and entry["held_delta"] > 0), None)
        if reserve_entry is None or any(entry["kind"] in {"commit", "release"} for entry in entries):
            return
        hold = CreditHold(context, row["id"], reserve_entry["amount_microusd"], reserve_entry["tariff_revision"],
                          store, current_app.extensions["enterprise_adapters"], dispatched=True)
        complete(hold, {"cost_usd": row["cost_usd"], "cost_basis": "usage"}, transition_id=transition_id)
    except CreditAdmissionError:
        raise
    except Exception as error:
        raise _failure(error) from None
