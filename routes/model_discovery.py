"""Public model discovery for explicit models and server-owned routing aliases."""

from flask import jsonify

from route_helpers import api_auth_required
from routes.auto_routes import openai_auto_route_models
from services.auto_route_service import AutoRouteService
from services.free_model_policy import free_model_aliases
from services.model_catalog_service import build_model_catalog, unified_model_payload


def register_model_discovery_route(app, csrf):
    @app.route("/v1/models", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_auth_required(required_scope="models")
    def list_unified_models():
        models = [
            unified_model_payload(model)
            for model in build_model_catalog(
                app.config["API_BASE_URLS"], AutoRouteService.list_routes()
            )
            if model["status"] != "disabled"
        ]
        models.extend(openai_auto_route_models())
        models.extend(free_model_aliases())
        return jsonify({"object": "list", "data": models})
