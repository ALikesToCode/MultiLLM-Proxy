"""Hierarchy administration uses dashboard sessions; workspace selection uses gateway keys."""
import re
from functools import wraps

from flask import g, jsonify, request

from route_helpers import api_authenticate_only, login_required
from routes.config_snapshots import json_errors
from routes.core import require_admin_dashboard_user
from services import tenant_hierarchy as tenants


def _revision():
    value = request.headers.get("If-Match")
    if value is None:
        raise tenants.TenantError("revision_required", 428)
    if not re.fullmatch(r'"[0-9]{1,16}"', value):
        raise tenants.TenantError("invalid_revision")
    return tenants._revision(int(value[1:-1]))


def _data():
    request.max_content_length = tenants.MAX_BODY_BYTES
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise tenants.TenantError("invalid_request")
    return value


def _reply(value, status=200):
    response = jsonify(value)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    if "revision" in value:
        response.headers["ETag"] = f'"{value["revision"]}"'
    return response


def register_tenant_routes(app, *, csrf=None, store=None):
    app.extensions["tenant_store"] = store or tenants.TenantStore()
    app.register_error_handler(tenants.TenantError, tenants.error_response)

    def is_tenant_route():
        return (request.path == "/admin/organisations" or request.path.startswith("/admin/organisations/")
                or request.path == "/v1/workspaces" or request.path.startswith("/v1/workspaces/"))

    def disabled_tenants():
        if is_tenant_route() and not tenants.enabled():
            return jsonify({"error": "not_found"}), 404, {"Cache-Control": "no-store"}
        if is_tenant_route():
            request.max_content_length = tenants.MAX_BODY_BYTES
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, disabled_tenants)

    @app.after_request
    def tenant_no_store(response):
        if is_tenant_route():
            response.headers["Cache-Control"] = "no-store"
        return response

    def call(operation, **values):
        return app.extensions["tenant_store"].request(operation, **values)

    def administrator(view):
        @wraps(view)
        @json_errors
        @login_required
        def guarded(*args, **kwargs):
            user = require_admin_dashboard_user()
            return view(user["username"], *args, **kwargs)
        return guarded

    @app.route("/admin/organisations", methods=["GET", "POST"])
    @administrator
    def organisations(actor):
        if request.method == "GET":
            return _reply(call("org_list"))
        return _reply(call("org_create", actor=actor, data=_data()), 201)

    @app.route("/admin/organisations/<org_id>", methods=["GET", "PATCH"])
    @administrator
    def organisation(actor, org_id):
        if request.method == "GET":
            return _reply(call("org_get", org_id=org_id))
        return _reply(call("org_update", actor=actor, org_id=org_id, revision=_revision(), data=_data()))

    @app.route("/admin/organisations/<org_id>/teams", methods=["GET", "POST"])
    @administrator
    def teams(actor, org_id):
        if request.method == "GET":
            return _reply(call("team_list", org_id=org_id))
        return _reply(call("team_create", actor=actor, org_id=org_id, data=_data()), 201)

    @app.patch("/admin/organisations/<org_id>/teams/<team_id>")
    @administrator
    def team(actor, org_id, team_id):
        return _reply(call("team_update", actor=actor, org_id=org_id, team_id=team_id,
                           revision=_revision(), data=_data()))

    @app.get("/admin/organisations/<org_id>/members")
    @administrator
    def members(actor, org_id):
        return _reply(call("member_list", org_id=org_id))

    @app.put("/admin/organisations/<org_id>/members/<principal>")
    @administrator
    def member(actor, org_id, principal):
        return _reply(call("member_set", actor=actor, org_id=org_id, principal=principal,
                           revision=_revision(), data=_data()))

    @app.get("/v1/workspaces")
    @api_authenticate_only(required_scope="models")
    def workspaces():
        user = g.authenticated_user
        return _reply(call("workspaces", principal=user.get("username") or user["id"]))

    @app.post("/v1/workspaces/switch")
    @api_authenticate_only(required_scope="models")
    def switch_workspace():
        user = g.authenticated_user
        principal = user.get("username") or user["id"]
        return _reply(call("binding_set", principal=principal, actor=principal,
                           revision=_revision(), data=_data()))

    # Existing API-key endpoints use this exemption; dashboard mutations retain CSRF.
    (csrf or app.extensions.get("csrf")).exempt(switch_workspace)
