from flask import jsonify, render_template, request

from route_helpers import login_required
from services.proxy_documentation_service import build_proxy_documentation


def register_documentation_routes(app, auth_service_cls) -> None:
    def documentation_payload():
        return build_proxy_documentation(
            app.config["API_BASE_URLS"],
            auth_service_cls,
            request.url_root.rstrip("/"),
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
