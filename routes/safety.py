"""Administrator controls and the internal, text-only moderation transport."""

import json
from contextlib import contextmanager

from flask import g, jsonify, request

from error_handlers import APIError
from routes.media_audio import media_fail_over
from routes.moderations import dispatch_candidate, moderation_request, validate_candidate
from services import audit_log
from services.auth_service import AuthService
from services.auto_route_service import AutoRouteService
from services.child_safety import HEADER, ChildSafetyScreen
from services.child_safety_settings import SafetyError, SafetySettingsStore

MAX_RESULT_BYTES = 4 * 1024 * 1024


def _result_body(response):
    data = bytearray()
    for chunk in response.iter_encoded():
        data.extend(chunk)
        if len(data) > MAX_RESULT_BYTES:
            raise SafetyError("moderation_result_invalid")
    return json.loads(data)


@contextmanager
def _screen_accounting():
    # Moderation cleanup must not mark the generation's reservation dispatched or ambiguous.
    context, request_id = getattr(g, "usage_context", None), getattr(g, "request_id", None)
    g.usage_context = None
    try:
        yield
    finally:
        g.usage_context, g.request_id = context, request_id


def _check_text(texts, app, auth, metrics, proxy):
    """Use the saved route without replacing the generation's routing/accounting metadata."""
    media = moderation_request({"input": texts})
    route = AutoRouteService.get_route(media.model)
    for candidate in route.candidates if route is not None else ():
        try:
            validate_candidate(app, auth, media, candidate)
        except (APIError, ValueError):
            continue
        response = dispatch_candidate(app, auth, metrics, proxy, media, candidate)
        try:
            if response.status_code == 200:
                return _result_body(response)
            if not media_fail_over(response):
                break
        finally:
            response.close()
    raise SafetyError("moderation_unavailable")


def check_text(texts, app, auth, metrics, proxy):
    with _screen_accounting():
        return _check_text(texts, app, auth, metrics, proxy)


def register_safety_routes(app, auth, metrics, proxy):
    store = SafetySettingsStore()
    app.extensions["child_safety"] = ChildSafetyScreen(store, lambda texts: check_text(texts, app, auth, metrics, proxy))

    def authenticate_settings():
        if request.path == "/admin/safety" and not AuthService.is_authenticated():
            return jsonify({"error": {"code": "authentication_required"}}), 401
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, authenticate_settings)

    @app.after_request
    def safety_response_headers(response):
        if getattr(g, "child_safety_result", None):
            response.headers[HEADER] = g.child_safety_result
        if request.path == "/admin/safety":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/admin/safety", methods=["GET", "POST"])
    def admin_safety():
        if not AuthService.is_authenticated():
            return jsonify({"error": {"code": "authentication_required"}}), 401
        user = AuthService.get_current_user() or {}
        if not user.get("is_admin"):
            return jsonify({"error": {"code": "admin_required"}}), 403
        try:
            if request.method == "GET":
                settings = store.get(fresh=True)
            else:
                request.max_content_length = 4096
                settings = store.configure(request.get_json(silent=True))
                audit_log.record("setting_change", "succeeded", actor=user.get("username"), target="child_safety",
                                 detail=json.dumps(settings.as_dict(), separators=(",", ":")))
            return jsonify({"settings": settings.as_dict()})
        except SafetyError as error:
            return jsonify({"error": {"code": error.code}}), error.status
