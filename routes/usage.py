"""Usage and budgets: `GET /v1/usage` for agents, the dashboard usage page, and the
administrator's per-key controls."""

import logging
from datetime import datetime, timedelta, timezone

from flask import g, jsonify, render_template, request

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_authenticate_only, login_required
from services import key_controls, usage_ledger, usage_store
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
    @app.route("/v1/usage", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only(required_scope="models")
    def api_usage():
        """The caller's own spend, remaining budget and recent daily totals."""
        user = g.authenticated_user
        principal = str(user.get("username") or user.get("id"))
        controls = key_controls.public(user)
        return jsonify({
            "object": "usage",
            "principal": principal,
            "key_prefix": user.get("api_key_prefix"),
            "budget": BudgetService.status(user),
            "controls": {name: controls[name] for name in ("allowed_models", "allowed_ips", "expires_at")},
            **usage_history(principal, _days()),
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
