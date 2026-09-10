"""Public model discovery for explicit models and server-owned routing aliases."""

from flask import jsonify

from error_handlers import APIError
from route_helpers import api_auth_required, login_required
from routes.auto_routes import openai_auto_route_models
from services.auto_route_service import AutoRouteService
from services.free_model_policy import free_model_aliases
from services.image_relay_catalog import refresh_image_relay_catalog
from services.model_catalog_service import build_model_catalog, unified_model_payload
from services.model_registry import ModelRegistry


def register_model_discovery_route(app, csrf, auth_service_cls, proxy_service_cls):
    def current_catalog():
        refresh_image_relay_catalog(app, auth_service_cls, proxy_service_cls)
        return build_model_catalog(
            app.config["API_BASE_URLS"], AutoRouteService.list_routes()
        )

    @app.route("/v1/models", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_auth_required(required_scope="models")
    def list_unified_models():
        models = [
            unified_model_payload(model)
            for model in current_catalog()
            if model["status"] != "disabled"
        ]
        models.extend(openai_auto_route_models())
        models.extend(free_model_aliases())
        return jsonify({"object": "list", "data": models})

    @app.route("/admin/models", methods=["GET"])
    @login_required
    def list_admin_models():
        current_user = auth_service_cls.get_current_user()
        if not current_user or not current_user.get("is_admin"):
            raise APIError("Only admin users can view models", status_code=403)
        built_in = {
            model.id: ModelRegistry.to_admin_dict(model)
            for model in ModelRegistry.list_models(app.config["API_BASE_URLS"])
        }
        models = []
        for model in current_catalog():
            models.append(
                {
                    "input_cost_per_million": None,
                    "output_cost_per_million": None,
                    **built_in.get(model["id"], {}),
                    **model,
                    **model["capabilities"],
                    "display_name": model["model"],
                }
            )
        return jsonify({"models": models})
