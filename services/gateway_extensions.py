"""Static Flask extension registration; callbacks are supplied explicitly in policy order."""
from flask import current_app, jsonify, request

from route_helpers import is_api_request_path, login_required
from services.auth_service import AuthService
from services.config_revision_sync import configure_sync, load_settings, supported_settings
from services.provider_catalog_refresh import refresh_provider_catalog_revision


def after_authentication():
    """Run static post-authentication collaborators once before admission and dispatch."""
    from flask import g
    if getattr(g, "gateway_authenticated_hooks_ran", False):
        return None
    g.gateway_authenticated_hooks_ran = True
    for hook in current_app.extensions.get("gateway_after_authentication", ()):
        refused = hook()
        if refused is not None:
            return refused
    return None


def register_retention(app):
    app.extensions.setdefault("gateway_after_authentication", []).append(request_policy_hook)


def request_policy_hook():
    from services.retention_policy import request_policy
    request_policy()
    return None


def register_cooldown_errors(app):
    from services.model_cooldown import ModelCooldownCapacity, ModelCooldownExhausted, cooldown_error_response
    def cooldown_failure(error):
        from flask import g
        g.gateway_cooldown_error = True
        return cooldown_error_response(error)
    for error in (ModelCooldownExhausted, ModelCooldownCapacity):
        app.register_error_handler(error, cooldown_failure)


def gateway_callbacks():
    from middleware.admission import register_admission
    from middleware.rate_limit_headers import register_rate_limit_headers
    return (register_retention, register_admission, register_cooldown_errors, register_rate_limit_headers)


def register_gateway_extensions(app, *, callbacks=(), revision_sync=None, security_refreshers=None):
    """Mount revision sync and explicitly supplied middleware without peer imports."""
    settings = revision_sync.settings if revision_sync is not None else supported_settings(load_settings())
    if settings.enabled:
        sync = revision_sync or configure_sync(settings, security_refreshers=security_refreshers,
                                                catalog_refresh=refresh_provider_catalog_revision)
        app.extensions["config_revision_sync"] = sync

        @app.before_request
        def require_config_security_freshness():
            # Cover every API entry, including forwarded/native protocols and MCP. Recovery
            # and admin status remain reachable while the authority is unavailable.
            protected = (is_api_request_path(request.path) and request.path.rstrip("/") not in {"/health", "/healthz"}
                or request.endpoint == "proxy" or request.path in {"/mcp", "/mcp/", "/googleai/chat/completions",
                                                                     "/api/backends/chat-completions/generate"})
            if request.method != "OPTIONS" and protected and not sync.security_ready():
                return jsonify({"error": {"code": "config_security_stale",
                    "message": "Security configuration freshness could not be verified"}}), 503, {"Cache-Control": "no-store"}
            return None

    @login_required
    def admin_status():
        if not (AuthService.get_current_user() or {}).get("is_admin"):
            return jsonify({"error": "admin_required"}), 403
        return jsonify(app.extensions["config_revision_sync"].status()), 200, {"Cache-Control": "no-store"}

    @app.get("/admin/config/revisions")
    def config_revision_status():
        if not settings.enabled:
            return jsonify({"error": "not_found"}), 404
        return admin_status()

    for callback in callbacks:
        callback(app)
