"""Explicit prompt publication and rendering, registered by the workbench."""

from functools import wraps

from flask import g, jsonify, request

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_authenticate_only, login_required, request_body_limit
from routes.core import require_admin_dashboard_user
from services import audit_log
from services.secret_firewall import protect_payload
from services.prompt_templates import (
    MAX_BODY_BYTES, PromptTemplateStore, enabled, render_template, validate_template,
)


def _json_errors(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except APIError as error:
            return jsonify(error.to_dict()), error.status_code
    return wrapper


def register_prompt_template_routes(app):
    # Run before Flask-WTF so disabled endpoints have no auth, CSRF or body side effects.
    def prompt_template_gate():
        if request.endpoint not in {"workbench_prompts", "prompt_template_render"}:
            return None
        if not enabled():
            return jsonify({"error": "not_found"}), 404
        request.max_content_length = MAX_BODY_BYTES
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, prompt_template_gate)
    csrf = app.extensions.get("csrf")

    @app.after_request
    def private_prompt_templates(response):
        if request.endpoint in {"workbench_prompts", "prompt_template_render"}:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/admin/workbench/prompts", methods=["GET", "POST"])
    @_json_errors
    @login_required
    def workbench_prompts():
        user = require_admin_dashboard_user()
        principal = user.get("username") or user.get("id")
        if request.method == "GET":
            if set(request.args) - {"after_slug", "after_version"} or any(len(request.args.getlist(key)) != 1 for key in request.args):
                raise APIError("Invalid template list fields", 400)
            after = None
            if request.args:
                version = request.args.get("after_version", "")
                if not version.isascii() or not version.isdecimal() or len(version) > 10:
                    raise APIError("Invalid template page cursor", 400)
                after = {"slug": request.args.get("after_slug"), "version": int(version)}
            return jsonify(PromptTemplateStore.list(principal, after))
        template = validate_template(json_object_body())
        protect_payload({"content": template["content"]}, user=user, knowledge=True)
        try:
            stored = PromptTemplateStore.create(principal, template)
        except APIError:
            audit_log.record("setting_change", "refused", actor=principal, target="prompt_templates", detail="operation=create")
            raise
        audit_log.record("setting_change", "succeeded", actor=principal, target="prompt_templates", detail="operation=create")
        return jsonify(stored), 201

    @app.route("/v1/prompt-templates/<slug>/render", methods=["POST", "OPTIONS"])
    @_json_errors
    @api_authenticate_only(required_scope="prompts:render")
    @request_body_limit(lambda: MAX_BODY_BYTES)
    def prompt_template_render(slug):
        body = json_object_body()
        if set(body) != {"version", "variables"}:
            raise APIError("Rendering requires exactly version and variables", 400)
        user = g.authenticated_user
        template = PromptTemplateStore.get(user.get("username") or user.get("id"), slug, body["version"])
        protect_payload({"content": template["content"], "variables": body["variables"]}, user=user, knowledge=True)
        return jsonify(render_template(template, body["variables"]))

    if csrf is not None:
        csrf.exempt(prompt_template_render)
