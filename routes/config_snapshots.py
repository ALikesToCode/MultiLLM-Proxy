"""Administrator-only snapshot review; existing session and CSRF protections apply."""
from functools import wraps

from flask import jsonify, request

from error_handlers import APIError

from route_helpers import login_required
from routes.core import require_admin_dashboard_user
from services import config_snapshots


def json_errors(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except APIError as error:
            return jsonify(error.to_dict()), error.status_code
    return wrapped


def register_config_snapshot_routes(app):
    def disabled_config_snapshots():
        if (request.path == "/admin/config/snapshots" or request.path.startswith("/admin/config/snapshots/")) and not config_snapshots.enabled():
            return jsonify({"error": "not_found"}), 404

    # Feature-off requests must be 404 even before session and CSRF checks.
    app.before_request_funcs.setdefault(None, []).insert(0, disabled_config_snapshots)

    @app.after_request
    def private_config_snapshots(response):
        if request.path == "/admin/config/snapshots" or request.path.startswith("/admin/config/snapshots/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/admin/config/snapshots", methods=["GET", "POST"])
    @json_errors
    @login_required
    def admin_config_snapshots():
        user = require_admin_dashboard_user()
        if request.method == "GET":
            return jsonify(config_snapshots.call("snapshot_list"))
        return jsonify(config_snapshots.create(request.get_json(silent=True), user, app.config["API_BASE_URLS"])), 201

    @app.get("/admin/config/snapshots/<identifier>/diff")
    @json_errors
    @login_required
    def admin_config_snapshot_diff(identifier):
        require_admin_dashboard_user()
        return jsonify(config_snapshots.diff(identifier, request.args.get("offset", "0")))

    @app.post("/admin/config/snapshots/<identifier>/apply")
    @json_errors
    @login_required
    def admin_config_snapshot_apply(identifier):
        user = require_admin_dashboard_user()
        return jsonify(config_snapshots.apply(identifier, request.get_json(silent=True), user))
