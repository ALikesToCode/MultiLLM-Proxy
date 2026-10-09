"""Administrator alert controls retain existing session and CSRF protection."""
from flask import jsonify, request

from services.auth_service import AuthService
from services import gateway_alerts


def register_alert_routes(app):
    def disabled_alerts():
        if request.path == "/admin/alerts" and not gateway_alerts.settings()[0]:
            return jsonify({"error": {"code": "not_found"}}), 404
        if request.path == "/admin/alerts" and not AuthService.is_authenticated():
            return jsonify({"error": {"code": "authentication_required"}}), 401
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, disabled_alerts)

    @app.after_request
    def private_alerts(response):
        if request.path == "/admin/alerts":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/admin/alerts", methods=["GET", "POST"])
    def admin_alerts():
        if not AuthService.is_authenticated():
            return jsonify({"error": {"code": "authentication_required"}}), 401
        if not (AuthService.get_current_user() or {}).get("is_admin"):
            return jsonify({"error": {"code": "admin_required"}}), 403
        try:
            if request.method == "GET":
                result = gateway_alerts.call("get")
            else:
                if request.content_length is not None and request.content_length > gateway_alerts.MAX_BYTES:
                    raise gateway_alerts.AlertError("gateway_alert_too_large", 413)
                result = gateway_alerts.configure(request.get_json(silent=True), set(app.config["API_BASE_URLS"]))
            return jsonify(result)
        except gateway_alerts.AlertError as error:
            return jsonify({"error": {"code": error.code}}), error.status
