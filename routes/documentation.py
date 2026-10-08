from flask import jsonify, render_template, request

from route_helpers import api_authenticate_only, login_required
from services.provider_catalog_refresh import refresh_model_catalogs
from services.proxy_documentation_service import (
    build_openapi_documentation,
    build_proxy_documentation,
)


def register_documentation_routes(app, auth_service_cls, proxy_service_cls) -> None:
    def documentation_payload():
        refresh_model_catalogs(app, auth_service_cls, proxy_service_cls)
        return build_proxy_documentation(
            app.config["API_BASE_URLS"],
            auth_service_cls,
            request.url_root.rstrip("/"),
            runtime_config=app.config,
        )

    @app.route("/docs")
    @login_required
    def proxy_documentation():
        documentation = documentation_payload()
        if request.args.get("format") == "json":
            return jsonify(documentation)
        return render_template(
            "documentation.html",
            documentation=documentation,
            user=auth_service_cls.get_current_user(),
        )

    @app.route("/docs.json")
    @login_required
    def proxy_documentation_json():
        return jsonify(documentation_payload())

    @api_authenticate_only(required_scope="models")
    def authenticated_openapi():
        return jsonify(build_openapi_documentation())

    @app.route("/openapi.json", methods=["GET"])
    def proxy_openapi_json():
        if auth_service_cls.is_authenticated():
            return jsonify(build_openapi_documentation())
        return authenticated_openapi()
