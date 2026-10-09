"""Static Flask extension registration; callbacks are supplied explicitly in policy order."""
from flask import current_app, jsonify, request

from route_helpers import is_api_request_path, login_required
from services.auth_service import AuthService
from services.config_revision_sync import configure_sync, load_settings, supported_settings
from services.provider_catalog_refresh import refresh_provider_catalog_revision

AUTHENTICATED_HOOK_ORDER = (
    "tenant_context_hook", "request_policy_hook", "prompt_injection_request_hook", "spillover_hook", "pii_request_hook",
    "responses_state_hook", "context_canary_request_hook", "generation_deadline_hook",
    "latency_slo_request_hook", "idempotency_request_hook", "admit",
)


def order_authenticated_hooks(app):
    """Keep policy boundaries independent of registrar invocation order."""
    positions = {name: position for position, name in enumerate(AUTHENTICATED_HOOK_ORDER)}
    app.extensions.setdefault("gateway_after_authentication", []).sort(
        key=lambda hook: positions.get(hook.__name__, len(positions)))


def register_authenticated_hook(app, hook):
    hooks = app.extensions.setdefault("gateway_after_authentication", [])
    if not any(existing.__name__ == hook.__name__ for existing in hooks):
        hooks.append(hook)
    order_authenticated_hooks(app)


def after_authentication():
    """Run static post-authentication collaborators once before admission and dispatch."""
    from flask import g
    if getattr(g, "gateway_authenticated_hooks_ran", False):
        return None
    g.gateway_authenticated_hooks_ran = True
    from services.tenant_hierarchy import current_tenant, enabled, tenant_context_hook
    # Preserve the default registrar list while resolving legacy identity on every request.
    if not enabled():
        g.tenant_context = current_tenant()
    elif not any(hook.__name__ == "tenant_context_hook" for hook in current_app.extensions.get("gateway_after_authentication", ())):
        refused = tenant_context_hook()
        if refused is not None:
            return refused
    for hook in current_app.extensions.get("gateway_after_authentication", ()):
        refused = hook()
        if refused is not None:
            g.pop("context_canary_scope", None)
            return refused
    return None


def register_tenants(app):
    from services.tenant_hierarchy import TenantError, enabled, error_response, tenant_context_hook
    app.register_error_handler(TenantError, error_response)
    if enabled():
        register_authenticated_hook(app, tenant_context_hook)


def register_retention(app):
    register_authenticated_hook(app, request_policy_hook)


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


def register_hosted_responses(app, *, csrf=None):
    from flask_wtf.csrf import CSRFProtect
    from routes.responses_state import register_responses_state
    register_responses_state(app, csrf or app.extensions.get("csrf") or CSRFProtect())


def managed_generation_request():
    """Only gateway protocol views, never provider-prefixed passthrough."""
    if request.method != "POST":
        return False
    if request.path in {"/v1/chat/completions", "/v1/messages", "/v1/responses",
                        "/intelligence/v1/chat/completions"}:
        return True
    return False


def register_injection_decision(app):
    from services.prompt_injection_detection import register_prompt_injection
    # No persisted route injection policy exists; key controls are supplied by
    # the detector from the authenticated principal. The operator policy is the default.
    register_prompt_injection(app, is_managed=managed_generation_request, route_policy=lambda: None)


def register_batch_spillover(app):
    from routes.gateway_batches import spillover_hook
    register_authenticated_hook(app, spillover_hook)


def gateway_callbacks(*, csrf=None):
    from functools import partial
    from middleware.admission import register_admission
    from middleware.rate_limit_headers import register_rate_limit_headers
    from services.context_canary_hook import register_context_canary
    from services.pii_redaction import register_pii_redaction
    return (register_tenants, register_retention, register_injection_decision, register_batch_spillover, register_pii_redaction,
            partial(register_hosted_responses, csrf=csrf), register_context_canary,
            register_deadline, register_latency_slo, register_managed_idempotency,
            register_admission, register_cooldown_errors, register_rate_limit_headers)


def verified_internal_transport():
    # API credentials and proxy-origin headers do not authenticate the internal hop.
    # No Flask-side transport verifier exists yet; keep internal budgets untrusted.
    return False


def generation_limits_ms():
    """Resolve existing intelligence route limits only for an opted-in deadline."""
    from services.generation_deadline import PUBLIC_HEADER
    if request.headers.get(PUBLIC_HEADER) is None:
        return ()
    body = request.get_json(silent=True)
    body = body if isinstance(body, dict) else {}
    if (request.path.startswith("/intelligence/") or body.get("model") == "auto:intelligence"
            or "routing" in body):
        from services.intelligence_store import IntelligenceStore
        policy = IntelligenceStore.policy()
        routing = body.get("routing")
        proposed = routing.get("deadline_ms") if isinstance(routing, dict) else None
        return (policy["deadline_ms"], proposed)
    return ()


def register_deadline(app):
    from services.generation_deadline import register_generation_deadline
    register_generation_deadline(app, verify_internal=verified_internal_transport, limits_ms=generation_limits_ms)


def latency_slo_candidate_policy(payload):
    """Read-only collaborator returns candidates after eligibility and approved lane selection."""
    callback = current_app.extensions.get("latency_slo_candidate_policy")
    return callback(payload) if callback is not None else None


def register_latency_slo(app):
    from services.latency_slo import register_latency_slo as register
    from services.latency_slo_candidates import register_latency_slo_candidates
    register_latency_slo_candidates(app)
    register(app, is_managed=managed_generation_request, candidates=latency_slo_candidate_policy)


def managed_policy_revision(payload):
    from services.managed_turn import idempotency_policy_revision
    return idempotency_policy_revision(payload)


def register_managed_idempotency(app):
    if app.extensions.get("gateway_managed_idempotency_registered"):
        return
    from middleware.idempotency import register_idempotency
    from services.idempotency_store import IdempotencyStore
    register_idempotency(app, store=IdempotencyStore(), policy_revision=managed_policy_revision)
    from routes.responses_state import defer_hosted_idempotency
    finalizers = app.after_request_funcs[None]
    finalizers[:] = [defer_hosted_idempotency(finalizer)
                    if finalizer.__name__ == "finalize_managed_failure" else finalizer for finalizer in finalizers]
    app.extensions["gateway_managed_idempotency_registered"] = True


def register_gateway_extensions(app, *, callbacks=(), revision_sync=None, security_refreshers=None):
    """Mount revision sync and explicitly supplied middleware without peer imports."""
    if app.extensions.get("gateway_extensions_registered"):
        return
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
    order_authenticated_hooks(app)

    from routes.alerts import register_alert_routes
    from services.gateway_alerts import observe
    register_alert_routes(app)
    app.extensions["gateway_alert_observer"] = observe
    app.extensions["gateway_extensions_registered"] = True
