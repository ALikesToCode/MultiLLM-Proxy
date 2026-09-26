"""Dashboard single sign-on through Cloudflare Access, the audit log page and page hardening."""

import logging
from typing import Optional

from flask import abort, jsonify, make_response, redirect, render_template, request, session, url_for

from route_helpers import login_required, request_api_key
from routes.core import is_safe_redirect_target, require_admin_dashboard_user
from services import audit_log, dashboard_sso
from services.auth_service import AuthService
from services.login_attempt_service import LoginAttemptService

logger = logging.getLogger(__name__)

# Templates load only same-origin scripts and styles and hold no inline code; JSON data
# blocks are not executed. Fetches, the service worker and the manifest stay same-origin.
CONTENT_SECURITY_POLICY = "; ".join((
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "manifest-src 'self'",
    "worker-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
))
PERMISSIONS_POLICY = "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
HSTS_SECONDS = 31536000
TOO_MANY_ATTEMPTS = "Too many sign-in attempts. Try again later."
NOT_ALLOWED = "This Cloudflare Access identity is not allowed to sign in to this dashboard."
NO_IDENTITY = ("This request did not carry a verified Cloudflare Access identity. "
               "Open the dashboard through its Cloudflare Access application and try again.")
NOT_VERIFIED = "Cloudflare Access could not verify this sign-in. Sign in to Cloudflare Access again, then retry."
KEYS_UNAVAILABLE = "Cloudflare Access sign-in cannot be checked right now. Try again shortly."

# Administrator changes recorded as setting_change events:
# endpoint -> (setting label, methods, where the changed item's name comes from).
AUDITED_SETTINGS = {
    "manage_users": ("account.create", frozenset({"POST"}), ("body", "username")),
    "delete_user": ("account.delete", frozenset({"DELETE"}), ("view", "username")),
    "rotate_api_key": ("account.rotate_key", frozenset({"POST"}), ("view", "username")),
    "admin_auto_routes": ("auto_route.update", frozenset({"PUT"}), ("body", "route_id")),
    "admin_auto_route_catalog": ("model_catalog.refresh", frozenset({"POST"}), None),
    "disable_admin_model": ("model.disable", frozenset({"POST"}), ("view", "model_id")),
    "knowledge_admin_sources_create": ("knowledge.source_create", frozenset({"POST"}), ("body", "url")),
    "knowledge_admin_sources_update": ("knowledge.source_update", frozenset({"PATCH"}), ("view", "identifier")),
    "knowledge_admin_sources_refresh": ("knowledge.source_refresh", frozenset({"POST"}), ("view", "identifier")),
    "knowledge_admin_jobs_cancel": ("knowledge.job_cancel", frozenset({"POST"}), ("view", "identifier")),
    "knowledge_admin_policy_update": ("knowledge.policy_update", frozenset({"PUT"}), None),
}


def apply_page_security_headers(response):
    """Harden HTML pages; static files and API responses keep their own headers."""
    if response.mimetype != "text/html" or request.path.startswith("/static/"):
        return response
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    response.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", f"max-age={HSTS_SECONDS}")
    return response


def _setting_target(source) -> Optional[str]:
    if source is None:
        return None
    kind, name = source
    if kind == "view":
        value = (request.view_args or {}).get(name)
    else:
        body = request.get_json(silent=True) if request.is_json else None
        value = body.get(name) if isinstance(body, dict) else request.form.get(name)
    return value if isinstance(value, str) else None


def record_setting_change(response) -> None:
    """Audit an administrator change made from a dashboard session, and refused attempts."""
    setting = AUDITED_SETTINGS.get(request.endpoint or "")
    if not setting or request.method not in setting[1] or request.headers.get("Authorization") or request_api_key():
        return
    session_user = session.get("user") if session.get("authenticated") is True else None
    actor = session_user.get("username") if isinstance(session_user, dict) else None
    status = response.status_code
    outcome = "succeeded" if 200 <= status < 300 else "refused" if status in (401, 403) else None
    if not actor or outcome is None:
        return
    try:
        target = _setting_target(setting[2])
    except Exception:
        target = None
    audit_log.record("setting_change", outcome, actor=actor, target=target, detail=f"setting={setting[0]} status={status}")


def _sign_in_page(status: int, error: Optional[str], retry_after: Optional[int] = None, **context):
    response = make_response(render_template("login.html", error=error, **context), status)
    if retry_after:
        response.headers["Retry-After"] = str(retry_after)
    return response


def _refusal(reason: str) -> tuple[int, str]:
    if reason in {"email_not_allowed", "account_unavailable"}:
        return 403, NOT_ALLOWED
    if reason in {"untrusted", "missing"}:
        return 403, NO_IDENTITY
    if reason in {"keys_unavailable", "unavailable"}:
        return 503, KEYS_UNAVAILABLE
    return 403, NOT_VERIFIED


def _account_active(username: str) -> bool:
    user = AuthService._load_user_by_username(username)
    return bool(user) and not user.get("revoked_at")


def register_dashboard_security_routes(app) -> None:
    @app.context_processor
    def dashboard_sso_context():
        return {"dashboard_sso": {
            "enabled": dashboard_sso.configured(),
            "only": dashboard_sso.sso_only(),
            "logout_url": dashboard_sso.logout_url(),
        }}

    @app.after_request
    def dashboard_security_headers(response):
        try:
            record_setting_change(response)
        except Exception as error:
            logger.warning("Setting change audit failed (%s)", type(error).__name__)
        return apply_page_security_headers(response)

    @app.route(dashboard_sso.ACCESS_LOGIN_PATH, methods=["GET", "POST"])
    def login_access():
        """Sign in with the Cloudflare Access identity the Worker verified.

        GET shows who Access verified and which account that maps to; the POST (with a
        CSRF token) starts the session. Every refusal is throttled and audited.
        """
        if not dashboard_sso.configured():
            abort(404)
        assertion = dashboard_sso.read_assertion(request.headers, request.method, request.path)
        client = assertion.client if assertion and assertion.client else request.remote_addr
        email = assertion.email if assertion and assertion.verified else None
        attempt = f"access:{email or ''}"
        # The validator rejects schemes, hosts, protocol-relative paths and backslashes.
        next_page = request.args.get("next")  # nosemgrep
        next_page = next_page if is_safe_redirect_target(next_page) else None

        decision = LoginAttemptService.check(client, attempt)
        if not decision.allowed:
            return _sign_in_page(429, TOO_MANY_ATTEMPTS, decision.retry_after)

        username = dashboard_sso.username_for_email(email) if email else None
        if assertion is None:
            reason: Optional[str] = "untrusted"
        elif not assertion.verified:
            reason = assertion.reason or "invalid"
        elif username is None:
            reason = "email_not_allowed"
        elif not _account_active(username):
            reason = "account_unavailable"
        else:
            reason = None
        # Signing in replaces the whole session; it can still fail if the account changed meanwhile.
        if reason is None and request.method == "POST" and dashboard_sso.sign_in(AuthService, username, assertion) is None:
            reason = "account_unavailable"

        if reason is not None:
            decision = LoginAttemptService.record_failure(client, attempt)
            audit_log.record("sign_in", "refused", actor=email, target=username,
                             detail=f"method=access reason={reason}")
            status, message = _refusal(reason)
            if not decision.allowed:
                status, message = 429, TOO_MANY_ATTEMPTS
            return _sign_in_page(status, message, decision.retry_after)

        if request.method == "GET":
            return _sign_in_page(200, None, access_confirmation={
                "email": email, "username": username, "next": next_page,
            })

        LoginAttemptService.record_success(client, attempt)
        audit_log.record("sign_in", "succeeded", actor=username, detail=f"method=access email={email}")
        return redirect(next_page or url_for("status_page"))

    @app.route("/admin/audit", endpoint="audit_log")
    @login_required
    def audit_log_page():
        """Administrator view of account writes and security events, newest first."""
        current_user = require_admin_dashboard_user()
        query = audit_log.parse_query(request.args)
        available = audit_log.available()
        result = audit_log.page(**query) if available else {"entries": [], "next": None}
        if "application/json" in request.headers.get("Accept", ""):
            return jsonify({"available": available, "entries": result["entries"], "next": result["next"]})
        return render_template(
            "audit.html",
            available=available,
            entries=result["entries"],
            next_cursor=result["next"],
            filters=query,
            actions=audit_log.ACTIONS,
            current_user=current_user,
        )
