"""Usage and budgets: `GET /v1/usage` for agents, the dashboard usage page, and the
administrator's per-key controls."""

import logging
import re
from datetime import datetime, timedelta, timezone

from flask import g, jsonify, render_template, request

from error_handlers import APIError
from middleware.rate_limit_headers import enabled as rate_limit_headers_enabled, usage_snapshot
from request_validation import json_object_body
from route_helpers import api_authenticate_only, login_required
from services import key_controls, usage_ledger, usage_store, tenant_governance
from services.auth_service import AuthService
from services.budget_service import BudgetService

logger = logging.getLogger(__name__)

MAX_DAYS = 90
MAX_GROUPS = 200


def _days(default: int = 30) -> int:
    try:
        return min(MAX_DAYS, max(1, int(request.args.get("days", default))))
    except (TypeError, ValueError):
        return default


def _range(days: int) -> tuple[str, str]:
    today = datetime.now(timezone.utc)
    return (today - timedelta(days=days - 1)).strftime("%Y-%m-%d"), today.strftime("%Y-%m-%d")


def _combined(rows: list) -> dict:
    totals = {name: 0 for name in usage_store.TOTAL_COLUMNS[:7]}
    buckets = [0] * len(usage_store.BUCKET_COLUMNS)
    for row in rows:
        for name in totals:
            totals[name] += row.get(name) or 0
        for index, count in enumerate(row.get("latency_buckets") or []):
            buckets[index] += count or 0
    return usage_store.summarize({**totals, "latency_buckets": buckets})


def usage_history(principal, days: int, *, by_principal: bool = False) -> dict:
    """Daily, per-model (and per-key) totals from the rollups; never raises."""
    since, until = _range(days)
    history = {"range": {"since": since, "until": until, "days": days}, "history_available": True,
               "daily": [], "models": [], "totals": _combined([])}
    try:
        store = usage_ledger.LEDGER.store()
        daily = store.summary("day", since, until, principal, days)
        history["daily"] = [usage_store.summarize(row) for row in daily]
        history["models"] = [usage_store.summarize(row) for row in store.summary(
            "model", since, until, principal, MAX_GROUPS)]
        history["totals"] = _combined(daily)
        if by_principal:
            history["principals"] = [usage_store.summarize(row) for row in store.summary(
                "principal", since, until, None, MAX_GROUPS)]
    except Exception as error:
        logger.warning("Usage history is unavailable (%s)", type(error).__name__)
        history["history_available"] = False
    return history


def register_usage_routes(app, csrf) -> None:
    register_governance_routes(app)
    @app.route("/v1/usage", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only(required_scope="models")
    def api_usage():
        """The caller's own spend, remaining budget and recent daily totals."""
        user = g.authenticated_user
        principal = str(user.get("username") or user.get("id"))
        controls = key_controls.public(user)
        since, until = _range(_days())
        workspace = tenant_governance.workspace_usage(user, since=since, until=until)
        if workspace:
            scoped = workspace["workspace"]
            return jsonify({"object": "usage", "principal": principal, "key_prefix": user.get("api_key_prefix"),
                "controls": {name: controls[name] for name in ("allowed_models", "allowed_ips", "expires_at")},
                "budget": {"daily_budget_usd": user.get("daily_budget_usd"),
                           "monthly_budget_usd": user.get("monthly_budget_usd")},
                "history_available": True, "range": scoped["range"], "daily": scoped["daily"], "models": scoped["models"],
                "totals": {key: scoped[key] for key in ("spent_micro_usd", "holds_micro_usd", "requests")}, **workspace})
        return jsonify({
            **({"rate_limits": usage_snapshot(user, request.remote_addr)}
               if rate_limit_headers_enabled() else {}),
            "object": "usage",
            "principal": principal,
            "key_prefix": user.get("api_key_prefix"),
            "budget": BudgetService.status(user),
            "controls": {name: controls[name] for name in ("allowed_models", "allowed_ips", "expires_at")},
            **usage_history(principal, _days()),
            **workspace,
        })

    @app.route("/usage")
    @login_required
    def usage_page():
        current_user = AuthService.get_current_user()
        return render_template("usage.html", user=current_user,
                               is_admin=bool(current_user and current_user.get("is_admin")))

    @app.route("/usage/data")
    @login_required
    def usage_data():
        current_user = AuthService.get_current_user() or {}
        is_admin = bool(current_user.get("is_admin"))
        requested = (request.args.get("principal") or "").strip()
        if not is_admin:
            principal = current_user.get("username")
        else:
            principal = requested or None
        payload = {"principal": principal, "is_admin": is_admin,
                   **usage_history(principal, _days(), by_principal=is_admin and principal is None)}
        if principal:
            record = AuthService.get_user_record(principal) if is_admin else AuthService.get_user_record(
                current_user.get("username"))
            payload["budget"] = BudgetService.status(record or {"username": principal})
            payload["controls"] = key_controls.public(record or {})
            if rate_limit_headers_enabled():
                payload["rate_limits"] = usage_snapshot(record or {"username": principal}, request.remote_addr)
        if is_admin:
            payload["ledger"] = usage_ledger.LEDGER.stats()
        return jsonify(payload)

    @app.route("/users/<username>/controls", methods=["PUT"])
    @login_required
    def update_key_controls(username: str):
        """Set an account's budgets, model allowlist, expiry and address ranges."""
        try:
            user = AuthService.set_key_controls(username, json_object_body())
        except APIError as error:
            return jsonify({"status": "error", "message": error.client_message}), error.status_code
        return jsonify({"status": "success", "user": user})


def register_governance_routes(app):
    if app.extensions.get("tenant_governance_routes_registered"):
        return
    app.extensions["tenant_governance_routes_registered"] = True

    def disabled_governance():
        if request.path.startswith("/admin/organisations/") and request.path.endswith("/governance"):
            if not tenant_governance.enabled():
                return jsonify({"error": {"code": "not_found"}}), 404
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, disabled_governance)

    @app.after_request
    def governance_budget_envelope(response):
        if tenant_governance.enabled() and response.status_code == 429 and response.is_json:
            payload = response.get_json(silent=True)
            if isinstance(payload, dict) and payload.get("error") == "tenant_budget_exceeded" and isinstance(payload.get("budget"), dict):
                payload["error"] = {"code": "tenant_budget_exceeded", "level": payload["budget"].get("level")}
                response.set_data(app.json.dumps(payload) + "\n")
        return response

    @app.errorhandler(tenant_governance.GovernanceError)
    def governance_error(error):
        return jsonify(error.payload), error.status

    def governance(org_id, team_id=None):
        user = AuthService.get_current_user() or {}
        if not user.get("is_admin"):
            raise tenant_governance.GovernanceError("administrator_required", 403)
        tenant_governance._scope(org_id, team_id)
        principal = str(user.get("username") or user.get("id") or "")
        role = tenant_governance.membership_role(principal, org_id)
        permission = "edit" if request.method == "PUT" else "budgets"
        if not tenant_governance.permitted(role, permission):
            raise tenant_governance.GovernanceError("tenant_role_denied", 403)
        values = {"org_id": org_id, "team_id": team_id}
        if request.method == "PUT":
            match = request.headers.get("If-Match")
            if match is None:
                raise tenant_governance.GovernanceError("revision_required", 428)
            if not re.fullmatch(r'"(?:0|[1-9][0-9]{0,15})"', match):
                raise tenant_governance.GovernanceError("revision_stale", 412)
            values.update(actor=principal, revision=int(match[1:-1]),
                          policy=tenant_governance.validate_policy(json_object_body()))
        result = tenant_governance.store().call("put" if request.method == "PUT" else "get", **values)
        response = jsonify(result)
        response.headers["ETag"] = f'"{result["policy"]["revision"]}"'
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/admin/organisations/<org_id>/governance", methods=["GET", "PUT"])
    @login_required
    def organisation_governance(org_id):
        return governance(org_id)

    @app.route("/admin/organisations/<org_id>/teams/<team_id>/governance", methods=["GET", "PUT"])
    @login_required
    def team_governance(org_id, team_id):
        return governance(org_id, team_id)
