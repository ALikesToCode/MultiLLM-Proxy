"""Broker callback and administrator-managed subject links."""
from copy import deepcopy
from functools import wraps

from flask import jsonify, redirect, request, session

from services.saml_federation import MAX_TOKEN_BYTES, SamlError, SamlFederation, load_config

SAML_PUBLIC_ENDPOINTS = frozenset({"saml_login", "saml_callback", "saml_acs", "saml_metadata"})


def admin_dashboard_user():
    from services.auth_service import AuthService
    if not AuthService.is_authenticated():
        raise SamlError("authentication_required", 401)
    user = AuthService.get_current_user()
    if not user or not user.get("is_admin"):
        raise SamlError("admin_required", 403)
    return user


def register_saml_federation_routes(app, csrf):
    service = app.extensions.get("saml_federation")
    if service is None:
        service = SamlFederation(load_config(callback_url=app.config.get("SAML_CALLBACK_URL")))
        app.extensions["saml_federation"] = service

    def guarded(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            try:
                return view(*args, **kwargs)
            except SamlError as error:
                return jsonify(error.envelope()), error.status
        return wrapped

    def gate():
        if request.path.startswith("/auth/saml/") or request.path == "/admin/saml/links" or request.path.startswith("/admin/saml/links/"):
            if not service.config.enabled:
                return jsonify({"error": "not_found"}), 404
            if request.content_length is not None and request.content_length > MAX_TOKEN_BYTES + 2048:
                return jsonify(SamlError("saml_request_invalid").envelope()), 400
        return None

    app.before_request_funcs.setdefault(None, []).insert(0, gate)

    @app.after_request
    def private_saml_response(response):
        if request.path.startswith("/auth/saml/") or request.path.startswith("/admin/saml/links"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/auth/saml/login")
    @guarded
    def saml_login():
        destination, state_digest = service.begin()
        session["saml_state_digest"] = state_digest
        return redirect(destination, code=302)

    @app.route("/auth/saml/callback", methods=["GET", "POST"])
    @csrf.exempt
    @guarded
    def saml_callback():
        values = request.args if request.method == "GET" else request.form
        if set(values) != {"token", "state"} or any(len(values.getlist(key)) != 1 for key in values):
            raise SamlError("saml_request_invalid")
        browser_state_digest = session.get("saml_state_digest", "")
        original_session = deepcopy(dict(session))
        try:
            service.complete(values["token"], values["state"], browser_state_digest)
        except SamlError:
            session.clear()
            session.update(original_session)
            raise
        session["saml_state_digest"] = browser_state_digest
        return redirect("/", code=302)

    @app.route("/auth/saml/acs", methods=["GET", "POST"])
    @csrf.exempt
    @guarded
    def saml_acs():
        raise SamlError("saml_native_unavailable", 503)

    @app.get("/auth/saml/metadata")
    @guarded
    def saml_metadata():
        raise SamlError("saml_native_unavailable", 503)

    @app.route("/admin/saml/links", methods=["GET", "PUT"])
    @guarded
    def saml_links():
        user = admin_dashboard_user()
        if request.method == "GET":
            offset = request.args.get("offset", "0")
            if not offset.isascii() or not offset.isdigit() or len(offset) > 6:
                raise SamlError("saml_link_invalid")
            return jsonify(service.list_links(int(offset)))
        csrf.protect()
        return jsonify(service.put_link(request.get_json(silent=True), user["username"]))

    @app.route("/admin/saml/links/<identifier>", methods=["GET", "PUT", "DELETE"])
    @guarded
    def saml_link(identifier):
        user = admin_dashboard_user()
        if request.method == "GET":
            result = service.get_link(identifier)
            linked = result.get("link")
            if linked is None:
                raise SamlError("saml_link_not_found", 404)
            return jsonify({"version": 1, "link": linked})
        csrf.protect()
        if request.method == "PUT":
            return jsonify(service.put_link(request.get_json(silent=True), user["username"], identifier))
        return jsonify(service.deactivate_link(identifier, user["username"]))
