"""Intersected workspace grants and durable multi-level monetary reservations."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
from functools import lru_cache

from flask import current_app, g, has_app_context, has_request_context

from error_handlers import APIError
from services import control_state_d1
from services.enterprise_contract import AuthorityOperation, MAX_INTEGER, TenantContext, legacy_tenant

logger = logging.getLogger(__name__)
PERMISSIONS = {
    "admin": frozenset({"edit", "budgets", "usage", "all_usage"}),
    "billing": frozenset({"budgets", "usage", "all_usage"}),
    "member": frozenset({"usage"}),
}
TABLES = ("tenant_governance_policies", "tenant_governance_reservations",
          "tenant_governance_components", "tenant_governance_baselines", "tenant_governance_audit")
SCHEMA_QUERIES = (
    "SELECT org_id,team_id,revision,models,tools,daily,monthly FROM tenant_governance_policies LIMIT 0",
    "SELECT id,principal_id,org_id,team_id,day,month,estimate,charged,state,revision,provider,model,price_basis,created_at,operation_id FROM tenant_governance_reservations LIMIT 0",
    "SELECT reservation_id,level,scope_org,scope_id,period_kind,period,limit_units FROM tenant_governance_components LIMIT 0",
    "SELECT principal_id,period,amount FROM tenant_governance_baselines LIMIT 0",
    "SELECT operation_id,actor,org_id,team_id,revision,kind,at FROM tenant_governance_audit LIMIT 0",
)
POLICY_FIELDS = frozenset({"models", "tools", "daily", "monthly"})


class GovernanceError(APIError):
    def __init__(self, code="tenant_governance_unavailable", status=503, *, level=None, period=None):
        self.code, self.status, self.level, self.period = code, status, level, period
        detail = {"code": code}
        if level:
            detail["level"] = level
        if period:
            detail["period"] = period
        super().__init__("The workspace governance operation could not be completed.", status, {"error": detail})


@lru_cache(maxsize=1)
def _warn_once():
    logger.warning("Invalid TENANT_GOVERNANCE_ENABLED; tenant governance disabled")


def enabled(env=None):
    value = (os.environ if env is None else env).get("TENANT_GOVERNANCE_ENABLED", "")
    flag = value.strip().lower() if isinstance(value, str) else "invalid"
    if flag in {"", "false", "0", "off", "no"}:
        return False
    if flag in {"true", "1", "on", "yes"}:
        return True
    _warn_once()
    return False


def permitted(role, permission):
    return permission in PERMISSIONS.get(role, ())


def _legacy_resolver(user):
    context = TenantContext(str(user.get("username") or user.get("id") or ""))
    return legacy_tenant(AuthorityOperation(context, context.principal_id, 0, "governance.resolve"))


def _no_role(principal_id, org_id):
    return None


@dataclass(frozen=True)
class GovernanceCollaborators:
    tenant_resolver: object = _legacy_resolver
    membership_role: object = _no_role
    store: object = None


_collaborators = GovernanceCollaborators()


def register_governance_collaborators(*, tenant_resolver=_legacy_resolver,
                                    membership_role=_no_role, store=None, app=None):
    """Register fixed trusted collaborators; caller metadata never selects a workspace."""
    if not callable(tenant_resolver) or not callable(membership_role):
        raise TypeError("Named tenant resolver and membership role functions required")
    if store is not None and not callable(getattr(store, "call", None)):
        raise TypeError("Governance store call interface required")
    collaborators = GovernanceCollaborators(tenant_resolver, membership_role, store)
    if app is not None:
        app.extensions["tenant_governance"] = collaborators
    else:
        global _collaborators
        _collaborators = collaborators
    return collaborators


def collaborators():
    return current_app.extensions.get("tenant_governance", _collaborators) if has_app_context() else _collaborators


def workspace_context(user=None):
    if not enabled():
        return None
    user = user if user is not None else (getattr(g, "authenticated_user", None) if has_request_context() else None)
    if user is None:
        return None
    try:
        context = collaborators().tenant_resolver(user)
        from services.tenant_hierarchy import principal_id
        if type(context) is not TenantContext or context.principal_id != principal_id(user.get("username") or user.get("id") or ""):
            raise GovernanceError("tenant_scope_denied", 403)
    except GovernanceError:
        raise
    except Exception:
        raise GovernanceError("tenant_scope_denied", 403) from None
    return context if context.org_id is not None else None


def context_dict(context):
    return asdict(context)


def membership_role(principal_id, org_id):
    try:
        return collaborators().membership_role(principal_id, org_id)
    except GovernanceError:
        raise
    except Exception:
        raise GovernanceError() from None


class D1GovernanceStore:
    def call(self, operation, **values):
        if not control_state_d1.using_d1():
            raise GovernanceError()
        try:
            result = control_state_d1.call("tenant_governance", operation, version=1, rpc=True, **values)
        except control_state_d1.intelligence_d1_store.PrivateIntelligenceError as error:
            raise GovernanceError(error.code, error.status) from None
        except Exception:
            raise GovernanceError() from None
        if not isinstance(result, dict) or result.get("version") != 1:
            raise GovernanceError()
        decision = result.get("decision")
        if isinstance(decision, dict) and decision.get("allowed") is False:
            raise GovernanceError(decision["code"], decision["status"],
                                  level=decision.get("level"), period=decision.get("period"))
        if result.get("error"):
            failure = result["error"]
            code = failure.get("code", "tenant_governance_unavailable")
            status = {"tenant_budget_exceeded": 429, "budget_exceeded": 429,
                      "revision_stale": 412, "reservation_conflict": 409}.get(code, 503)
            raise GovernanceError(code, status, level=failure.get("level"), period=failure.get("period"))
        return {key: value for key, value in result.items() if key != "version"}


def store():
    return collaborators().store or D1GovernanceStore()


def validate_policy(value):
    if not isinstance(value, dict) or set(value) - POLICY_FIELDS:
        raise GovernanceError("invalid_governance_policy", 400)
    result = {key: value.get(key) for key in POLICY_FIELDS}
    for key in ("daily", "monthly"):
        amount = result[key]
        if amount is not None and (type(amount) is not int or not 0 <= amount < MAX_INTEGER):
            raise GovernanceError("invalid_governance_policy", 400)
    for key in ("models", "tools"):
        entries = result[key]
        if entries is not None and (not isinstance(entries, list) or len(entries) > 64 or
                any(not isinstance(entry, str) or re.fullmatch(r"[A-Za-z0-9._:/+@*\-]{1,256}", entry) is None for entry in entries)):
            raise GovernanceError("invalid_governance_policy", 400)
    return result


def _matches(patterns, candidate):
    if patterns is None:
        return True
    if not isinstance(candidate, str) or not candidate.strip():
        return False
    return any(re.fullmatch(".*".join(re.escape(part) for part in pattern.lower().split("*")),
                            candidate.strip().lower()) for pattern in patterns)


def grant_allowed(existing_allowed, candidate, *, user=None, kind="models", context=None):
    """Every configured ancestor intersects the existing key decision."""
    if not enabled():
        return existing_allowed
    context = context if context is not None else workspace_context(user)
    if context is None or context.org_id is None:
        return existing_allowed
    if kind not in {"models", "tools"}:
        raise ValueError("Unknown grant kind")
    policies = store().call("policies", context=context_dict(context))["policies"]
    return existing_allowed and all(_matches(policy[kind], candidate) for policy in policies)


def eligibility_allowed(existing_allowed, model):
    if not enabled() or not has_request_context():
        return existing_allowed
    user = getattr(g, "authenticated_user", None)
    if workspace_context(user) is None:
        return existing_allowed
    from services.key_controls import model_allowed
    key_allowed = model_allowed(user, model)
    return existing_allowed and key_allowed


def units(value):
    if isinstance(value, bool) or value is None:
        raise GovernanceError("unpriced_reservation", 503)
    try:
        number = Decimal(str(value)) * 1_000_000
        if not number.is_finite() or number < 0 or number >= MAX_INTEGER:
            raise ValueError
        return int(number.to_integral_value(rounding=ROUND_CEILING))
    except (ValueError, ArithmeticError):
        raise GovernanceError("unpriced_reservation", 503) from None


def reserve_budget(user, estimate_usd, now, budget_service):
    from services.budget_service import BudgetDecision, BudgetUnavailable, limits, periods
    try:
        context = workspace_context(user)
        if context is None:
            return None
        amount = units(estimate_usd)
        period = periods(now)
        daily, monthly = limits(user)
        base_day = base_month = 0
        if daily is not None or monthly is not None:
            state = budget_service._state(context.principal_id)
            budget_service._refresh(context.principal_id, state, period)
            with budget_service._lock:
                day, month, inflight = budget_service._spent(state, period)
            base_day, base_month = units(day + inflight), units(month + inflight)
        identity = "tg_" + uuid.uuid4().hex
        store().call("reserve", id=identity, context=context_dict(context), amount=amount,
            day=period["day"], month=period["month"],
            key_daily=None if daily is None else units(daily),
            key_monthly=None if monthly is None else units(monthly),
            base_day=base_day, base_month=base_month)
        if has_request_context():
            # Accounting clears usage_context before recording its final row.
            g.tenant_governance_reservation = identity
            g.tenant_governance_principal = context.principal_id
        return BudgetDecision(True, reservation=identity)
    except (GovernanceError, BudgetUnavailable) as error:
        if isinstance(error, BudgetUnavailable):
            error = GovernanceError()
        details = {"level": error.level, "period": error.period} if error.level else {}
        return BudgetDecision(False, error=error.code, status_code=error.status,
            message="The workspace budget could not admit this request.", details=details)


def governance_reservation(identity):
    return isinstance(identity, str) and identity.startswith("tg_")


def dispatch(identity, *, authority=None):
    if not governance_reservation(identity):
        return False
    (authority or store()).call("dispatch", id=identity)
    return True


def complete(identity, row, *, before_dispatch=False, cached=False, cancelled=False, authority=None):
    if not governance_reservation(identity):
        return False
    model = row.get("selected_model")
    model = model if isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9._:/+@\-]{1,256}", model) else None
    cost = row.get("cost_usd")
    measured = cost is not None and row.get("cost_basis") == "usage" and not cached
    (authority or store()).call("settle", id=identity, cost=0 if before_dispatch or cached or cancelled else units(cost) if measured else None,
        provider=model.split(":", 1)[0] if model and ":" in model else None, model=model,
        price_basis="released" if before_dispatch or cancelled else "cache" if cached else row.get("cost_basis"),
        before_dispatch=before_dispatch)
    return True


def capture_cost(row):
    if not has_request_context():
        return
    identity = getattr(g, "tenant_governance_reservation", None)
    if governance_reservation(identity) and row.get("principal") == getattr(g, "tenant_governance_principal", None):
        complete(identity, row, cached=row.get("cost_basis") == "cache")


def workspace_usage(user, *, since="0000-01-01", until="9999-12-31"):
    context = workspace_context(user)
    if context is None:
        return {}
    role = membership_role(context.principal_id, context.org_id)
    if not permitted(role, "usage"):
        raise GovernanceError("tenant_role_denied", 403)
    return {"workspace": store().call("usage", context=context_dict(context), role=role, since=since, until=until)}


def _scope(org_id, team_id):
    try:
        TenantContext("scope", org_id, team_id)
    except (ValueError, TypeError):
        raise GovernanceError("invalid_tenant_scope", 400) from None
    if org_id is None:
        raise GovernanceError("invalid_tenant_scope", 400)
    return org_id, team_id or ""


def _policy(row):
    result = {"revision": row["revision"], "models": json.loads(row["models"]) if row["models"] is not None else None,
            "tools": json.loads(row["tools"]) if row["tools"] is not None else None,
            "daily": row["daily"], "monthly": row["monthly"]}
    try:
        validate_policy({key: result[key] for key in POLICY_FIELDS})
    except GovernanceError:
        raise GovernanceError() from None
    return result


class SQLiteGovernanceStore:
    """Injected SQLite adapter. Migration application belongs to the operator."""
    def __init__(self, connect):
        self.connect = connect

    @contextmanager
    def transaction(self):
        db = self.connect()
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            for query in SCHEMA_QUERIES:
                db.execute(query)
            yield db
            db.commit()
        except GovernanceError:
            db.rollback()
            raise
        except (sqlite3.Error, OSError, ValueError, TypeError, KeyError):
            db.rollback()
            raise GovernanceError() from None
        finally:
            db.close()

    def call(self, operation, **values):
        with self.transaction() as db:
            if operation in {"get", "put"}:
                return self._admin(db, operation, values)
            if operation == "policies":
                context = TenantContext(**values["context"])
                return {"policies": self._policies(db, context)}
            if operation == "reserve":
                return self._reserve(db, values)
            if operation in {"settle", "dispatch"}:
                return self._settle(db, operation, values)
            if operation == "reconcile":
                return self._reconcile(db, values)
            if operation == "usage":
                return self._usage(db, values)
            raise GovernanceError("invalid_governance_operation", 400)

    def _policies(self, db, context):
        return [_policy(row) for row in db.execute(
            "SELECT * FROM tenant_governance_policies WHERE org_id=? AND (team_id='' OR team_id=?)",
            (context.org_id, context.team_id or ""))]

    def _admin(self, db, operation, values):
        org, team = _scope(values["org_id"], values.get("team_id"))
        row = db.execute("SELECT * FROM tenant_governance_policies WHERE org_id=? AND team_id=?", (org, team)).fetchone()
        revision = row["revision"] if row else 0
        if operation == "get":
            return {"policy": _policy(row) if row else {"revision": 0, **dict.fromkeys(POLICY_FIELDS)}}
        policy = validate_policy(values["policy"])
        if type(values["revision"]) is not int or values["revision"] != revision:
            raise GovernanceError("revision_stale", 412)
        actor = TenantContext(values["actor"]).principal_id
        db.execute("""INSERT INTO tenant_governance_policies VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(org_id,team_id) DO UPDATE SET revision=excluded.revision,models=excluded.models,
            tools=excluded.tools,daily=excluded.daily,monthly=excluded.monthly""",
            (org, team, revision + 1, None if policy["models"] is None else json.dumps(policy["models"]),
             None if policy["tools"] is None else json.dumps(policy["tools"]), policy["daily"], policy["monthly"]))
        db.execute("INSERT INTO tenant_governance_audit VALUES (?,?,?,?,?,?,?)",
                   (uuid.uuid4().hex, actor, org, team, revision + 1, "policy", datetime.now(timezone.utc).isoformat()))
        return {"policy": {"revision": revision + 1, **policy}}

    def _components(self, db, context, values):
        components = []
        scopes = [("key", "", context.principal_id, values["key_daily"], values["key_monthly"])]
        for team in [""] + ([context.team_id] if context.team_id else []):
            row = db.execute("SELECT daily,monthly FROM tenant_governance_policies WHERE org_id=? AND team_id=?",
                             (context.org_id, team)).fetchone()
            scopes.append(("team" if team else "organisation", context.org_id, team or context.org_id,
                           row["daily"] if row else None, row["monthly"] if row else None))
        for level, org, scoped, daily, monthly in scopes:
            for kind, period, limit in (("daily", values["day"], daily), ("monthly", values["month"], monthly)):
                components.append((level, org, scoped, kind, period, limit))
        return components

    def _reserve(self, db, values):
        context = TenantContext(**values["context"])
        if context.org_id is None:
            raise GovernanceError("tenant_scope_denied", 403)
        amount = values["amount"]
        if type(amount) is not int or not 0 <= amount < MAX_INTEGER:
            raise GovernanceError("unpriced_reservation", 503)
        if db.execute("SELECT id FROM tenant_governance_reservations WHERE id=?", (values["id"],)).fetchone():
            raise GovernanceError("reservation_conflict", 409)
        components = self._components(db, context, values)
        for period, baseline in ((values["day"], values["base_day"]), (values["month"], values["base_month"])):
            db.execute("INSERT OR IGNORE INTO tenant_governance_baselines VALUES (?,?,?)", (context.principal_id, period, baseline))
        for level, org, scoped, kind, period, limit in components:
            if limit is None:
                continue
            total = db.execute("""SELECT COALESCE(SUM(CASE WHEN r.state!='settled' THEN r.estimate
                WHEN c.period=? THEN r.charged ELSE 0 END),0) FROM tenant_governance_components c
                JOIN tenant_governance_reservations r ON r.id=c.reservation_id
                WHERE c.level=? AND c.scope_org=? AND c.scope_id=? AND c.period_kind=?""",
                (period, level, org, scoped, kind)).fetchone()[0]
            if level == "key":
                total += db.execute("SELECT amount FROM tenant_governance_baselines WHERE principal_id=? AND period=?",
                                    (context.principal_id, period)).fetchone()[0]
            if total >= limit or amount > limit - total:
                raise GovernanceError("budget_exceeded" if level == "key" else "tenant_budget_exceeded", 429,
                                      level=level, period=kind)
        db.execute("""INSERT INTO tenant_governance_reservations
            (id,principal_id,org_id,team_id,day,month,estimate,state,created_at,operation_id) VALUES (?,?,?,?,?,?,?,'reserved',?,?)""",
            (values["id"], context.principal_id, context.org_id, context.team_id or "", values["day"], values["month"],
             amount, datetime.now(timezone.utc).isoformat(), uuid.uuid4().hex))
        db.executemany("INSERT INTO tenant_governance_components VALUES (?,?,?,?,?,?,?)",
                       [(values["id"], *component) for component in components])
        return {"id": values["id"]}

    def _settle(self, db, operation, values):
        row = db.execute("SELECT * FROM tenant_governance_reservations WHERE id=?", (values["id"],)).fetchone()
        if row is None:
            raise GovernanceError("reservation_conflict", 409)
        if row["state"] in {"settled", "unknown"}:
            if (row["state"] == "settled" and operation == "settle" and values.get("cost") is not None
                    and row["charged"] != values["cost"]):
                raise GovernanceError("reservation_conflict", 409)
            return {"state": row["state"]}
        if operation == "dispatch":
            db.execute("UPDATE tenant_governance_reservations SET state='dispatched',revision=revision+1 WHERE id=?", (values["id"],))
            return {"state": "dispatched"}
        if values.get("before_dispatch") and row["state"] != "reserved":
            raise GovernanceError("reservation_conflict", 409)
        cost = values["cost"]
        if cost is not None and (type(cost) is not int or not 0 <= cost < MAX_INTEGER):
            raise GovernanceError("invalid_governance_cost", 400)
        state = "unknown" if cost is None else "settled"
        db.execute("""UPDATE tenant_governance_reservations SET state=?,charged=?,provider=?,model=?,price_basis=?,
            revision=revision+1 WHERE id=?""", (state, cost, values.get("provider"), values.get("model"),
                                               values.get("price_basis"), values["id"]))
        return {"state": state}

    def _reconcile(self, db, values):
        from services.credits_ledger import context_owner
        cost, revision, transition = values.get("cost"), values.get("revision"), values.get("transition_id")
        if (not isinstance(values.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_:.\-]{1,128}", values["id"])
                or type(values.get("authorized_adjustment", False)) is not bool
                or type(revision) is not int or not 0 <= revision < MAX_INTEGER
                or not isinstance(transition, str) or not re.fullmatch(r"[a-f0-9]{32}", transition)
                or cost is not None and (type(cost) is not int or not 0 <= cost < MAX_INTEGER)):
            raise GovernanceError("invalid_governance_operation", 400)
        if values.get("admin") is not True:
            raise GovernanceError("admin_required", 403)
        reason, evidence = values.get("reason"), values.get("evidence")
        label = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"
        adjustment = values.get("authorized_adjustment", False)
        if (not isinstance(reason, str) or not re.fullmatch(label, reason)
                or adjustment is not True and (not isinstance(evidence, str) or not re.fullmatch(label, evidence))
                or adjustment is True and evidence is not None):
            raise GovernanceError("reconciliation_evidence_required", 400)
        document = json.dumps([values["id"], revision, cost, reason, evidence, adjustment], separators=(",", ":"))
        fingerprint = "reconcile:" + hashlib.sha256(document.encode()).hexdigest()
        row = db.execute("SELECT * FROM tenant_governance_reservations WHERE id=?", (values["id"],)).fetchone()
        if row is None:
            raise GovernanceError("reservation_conflict", 409)
        previous = db.execute("SELECT actor,kind FROM tenant_governance_audit WHERE operation_id=?", (transition,)).fetchone()
        if previous:
            if previous["actor"] != row["id"] or previous["kind"] != fingerprint:
                raise GovernanceError("reservation_conflict", 409)
        elif row["revision"] != revision or row["state"] not in {"dispatched", "unknown"}:
            raise GovernanceError("reservation_conflict", 409)
        else:
            db.execute("UPDATE tenant_governance_reservations SET state=?,charged=?,revision=revision+1,operation_id=? WHERE id=?",
                       ("unknown" if cost is None else "settled", cost, transition, row["id"]))
            db.execute("INSERT INTO tenant_governance_audit VALUES (?,?,?,?,?,?,?)",
                       (transition, row["id"], row["org_id"], row["team_id"], revision + 1, fingerprint,
                        datetime.now(timezone.utc).isoformat()))
        context = TenantContext(row["principal_id"], row["org_id"], row["team_id"] or None)
        return {"applied": previous is None, "reservation": {
            "id": row["id"], "principal": context_owner(context), "day": row["day"], "month": row["month"],
            "revision": revision + 1, "state": "unknown" if cost is None else "reconciled",
            "cost_usd": None if cost is None else cost / 1_000_000, "transition_id": transition,
            "settlement_id": row["id"], "basis": "adjustment" if adjustment else "provider",
            "input_tokens": None, "output_tokens": None}}

    def _usage(self, db, values):
        context = TenantContext(**values["context"])
        role = values["role"]
        if not permitted(role, "usage"):
            raise GovernanceError("tenant_role_denied", 403)
        since, until = values.get("since", "0000-01-01"), values.get("until", "9999-12-31")
        params = (context.org_id, context.team_id or "", context.team_id or "",
                  int(permitted(role, "all_usage")), context.principal_id, since, until)
        totals = dict(db.execute("""SELECT COALESCE(SUM(charged),0) AS spent_micro_usd,
            COALESCE(SUM(CASE WHEN state!='settled' THEN estimate ELSE 0 END),0) AS holds_micro_usd,
            COUNT(*) AS requests FROM tenant_governance_reservations WHERE org_id=? AND (?='' OR team_id=?)
            AND (?=1 OR principal_id=?) AND day>=? AND day<=?""", params).fetchone())
        models = [dict(row) for row in db.execute("""SELECT provider,model,price_basis,COUNT(*) AS requests,
            COALESCE(SUM(charged),0) AS spent_micro_usd FROM tenant_governance_reservations
            WHERE org_id=? AND (?='' OR team_id=?) AND (?=1 OR principal_id=?) AND day>=? AND day<=?
            GROUP BY provider,model,price_basis ORDER BY model LIMIT 200""", params)]
        daily = [dict(row) for row in db.execute("""SELECT day,COUNT(*) AS requests,COALESCE(SUM(charged),0) AS spent_micro_usd
            FROM tenant_governance_reservations WHERE org_id=? AND (?='' OR team_id=?)
            AND (?=1 OR principal_id=?) AND day>=? AND day<=? GROUP BY day ORDER BY day LIMIT 90""", params)]
        result = {"org_id": context.org_id, "team_id": context.team_id, "principal_id": context.principal_id,
                  "cost_description": "Gateway cost estimates, not invoices", **totals, "models": models, "daily": daily,
                  "range": {"since": since, "until": until}}
        if permitted(role, "all_usage"):
            org_total = dict(db.execute("""SELECT COALESCE(SUM(charged),0) AS spent_micro_usd,
                COALESCE(SUM(CASE WHEN state!='settled' THEN estimate ELSE 0 END),0) AS holds_micro_usd
                FROM tenant_governance_reservations WHERE org_id=? AND day>=? AND day<=?""", (context.org_id, since, until)).fetchone())
            result["organisation"] = org_total
            result["team"] = totals if context.team_id else None
        return result
