"""Administrator-only read-only descriptor for explicit enterprise contracts."""
from flask import jsonify, request

from route_helpers import login_required
from routes.config_snapshots import json_errors
from routes.core import require_admin_dashboard_user
from services import enterprise_contract as contracts


def register_enterprise_preview_routes(app):
    app.extensions["enterprise_adapters"] = contracts.register_enterprise_adapters()

    def disabled_enterprise_preview():
        if request.path != "/admin/enterprise/preview":
            return None
        if not contracts.preview_enabled():
            return jsonify({"error": "not_found"}), 404
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            return jsonify({"error": "method_not_allowed"}), 405, {"Allow": "GET, HEAD, OPTIONS"}
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, disabled_enterprise_preview)

    @app.get("/admin/enterprise/preview")
    @json_errors
    @login_required
    def admin_enterprise_preview():
        require_admin_dashboard_user()
        response = jsonify(contracts.preview_descriptor(app.extensions["enterprise_adapters"]))
        response.headers["Cache-Control"] = "no-store"
        return response
