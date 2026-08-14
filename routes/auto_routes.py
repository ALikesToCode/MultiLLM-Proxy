import logging
from collections.abc import Callable

from flask import Response, g, has_request_context, jsonify, request

from error_handlers import APIError
from providers.registry import get_registry
from services.auto_route_service import AutoRoute, AutoRouteService
from services.model_catalog_service import build_model_catalog
from services.model_registry import ModelRegistry
from services.provider_catalog_service import (
    PROVIDER_CATALOG_SPECS,
    ProviderCatalogService,
)

# Payment-required responses mean this candidate cannot serve the request with
# its current credentials. Explicit auto routes may safely try the next
# provider because the rejected candidate did not perform a generation.
AUTO_ROUTE_FALLBACK_STATUS_CODES = frozenset({401, 402, 403, 404, 429})
logger = logging.getLogger(__name__)


def _is_fallback_response(response: Response) -> bool:
    if response.status_code in AUTO_ROUTE_FALLBACK_STATUS_CODES:
        return True
    return response.status_code == 503 and response.headers.get(
        "X-MultiLLM-Circuit-State"
    ) in {"open", "half_open"}


def _buffer_failure(response: Response) -> Response:
    body = response.get_data()
    status_code = response.status_code
    headers = dict(response.headers)
    response.close()
    return Response(body, status=status_code, headers=headers)


def _decorate_response(
    response: Response,
    route: AutoRoute,
    selected_model: str,
    selected_priority: int,
    attempts: int,
) -> Response:
    selected_provider, _ = ModelRegistry.parse_model_id(selected_model)
    route_decision = "auto-primary" if selected_priority == 0 else "auto-failover"
    response.headers["X-MultiLLM-Auto-Route"] = route.id
    response.headers["X-MultiLLM-Auto-Selected-Model"] = selected_model
    response.headers["X-MultiLLM-Auto-Attempts"] = str(attempts)
    response.headers["X-MultiLLM-Auto-Selected-Priority"] = str(selected_priority + 1)
    if has_request_context():
        g.multillm_provider = selected_provider
        g.multillm_model = selected_model
        g.multillm_route_decision = route_decision
    return response


def dispatch_auto_route_chat_completion(
    payload: dict,
    *,
    validate_candidate: Callable[[str], None],
    dispatch_candidate: Callable[[dict, str, str], Response],
) -> Response:
    """Run an explicit priority list through injected validation and transport."""
    route = AutoRouteService.get_route(payload.get("model"))
    if route is None:
        raise APIError(
            f"Auto route not found: {payload.get('model')}",
            status_code=404,
        )

    attempts = 0
    last_failure: Response | None = None
    last_model = ""
    last_priority = 0
    for priority, candidate in enumerate(route.candidates):
        try:
            validate_candidate(candidate)
        except (APIError, ValueError) as error:
            logger.info(
                "Skipping unavailable auto route candidate %s (%s)",
                candidate,
                type(error).__name__,
            )
            continue

        attempts += 1
        candidate_payload = dict(payload)
        candidate_payload["model"] = candidate
        route_decision = "auto-primary" if priority == 0 else "auto-failover"
        response = dispatch_candidate(
            candidate_payload,
            candidate,
            route_decision,
        )
        if not _is_fallback_response(response):
            if last_failure is not None:
                last_failure.close()
            return _decorate_response(
                response,
                route,
                candidate,
                priority,
                attempts,
            )

        if last_failure is not None:
            last_failure.close()
        last_failure = _buffer_failure(response)
        last_model = candidate
        last_priority = priority

    if last_failure is not None:
        return _decorate_response(
            last_failure,
            route,
            last_model,
            last_priority,
            attempts,
        )
    raise APIError(
        f"No configured provider is available for auto route: {route.id}",
        status_code=503,
    )


def openai_auto_route_models() -> list[dict]:
    return [
        {
            "id": route.id,
            "object": "model",
            "created": 0,
            "owned_by": "multillm-auto",
            "status": "available",
        }
        for route in AutoRouteService.list_routes()
    ]


def _provider_is_configured(auth_service_cls, provider: str) -> bool:
    if provider == "googleai":
        return bool(auth_service_cls.get_google_token())
    if provider == "nanogpt":
        return bool(auth_service_cls.get_api_keys(provider))
    return bool(auth_service_cls.get_api_key(provider))


def _admin_payload(app, auth_service_cls) -> dict:
    stored_routes = AutoRouteService.list_routes()
    catalog_updated_at: dict[str, str] = {}
    for model in ProviderCatalogService.list_models():
        catalog_updated_at[model.provider] = max(
            catalog_updated_at.get(model.provider, ""),
            model.discovered_at,
        )

    model_catalog = build_model_catalog(
        app.config["API_BASE_URLS"],
        stored_routes,
    )

    provider_ids = sorted(get_registry(app.config["API_BASE_URLS"]))
    configured_by_provider = {
        provider: _provider_is_configured(auth_service_cls, provider)
        for provider in provider_ids
    }

    providers = [
        {
            "id": provider,
            "configured": configured_by_provider[provider],
            "credential_env": list(
                auth_service_cls.provider_credential_env_names(provider)
            ),
            "models": [
                model["model"]
                for model in model_catalog
                if model["provider"] == provider
            ],
            "catalog_path": (
                PROVIDER_CATALOG_SPECS[provider].proxy_path
                if provider in PROVIDER_CATALOG_SPECS
                else None
            ),
            "catalog_updated_at": catalog_updated_at.get(provider),
        }
        for provider in provider_ids
    ]

    model_catalog = [
        {
            **model,
            "configured": configured_by_provider[model["provider"]],
        }
        for model in model_catalog
    ]
    model_catalog_by_id = {model["id"]: model for model in model_catalog}

    routes = []
    for route in stored_routes:
        candidates = []
        for priority, model_id in enumerate(route.candidates, start=1):
            provider, provider_model = ModelRegistry.parse_model_id(model_id)
            candidates.append(
                {
                    "model_id": model_id,
                    "provider": provider,
                    "model": provider_model,
                    "priority": priority,
                    "configured": configured_by_provider[provider],
                    "status": model_catalog_by_id[model_id]["status"],
                }
            )
        routes.append(
            {
                "id": route.id,
                "candidates": candidates,
                "updated_at": route.updated_at,
            }
        )
    return {
        "routes": routes,
        "providers": providers,
        "model_catalog": model_catalog,
        "fallback_statuses": sorted(AUTO_ROUTE_FALLBACK_STATUS_CODES),
    }


def _require_admin(auth_service_cls) -> None:
    current_user = auth_service_cls.get_current_user()
    if not current_user or not current_user.get("is_admin"):
        raise APIError(
            "Only admin users can manage auto routes",
            status_code=403,
        )


def register_auto_route_admin_routes(
    app,
    login_required,
    auth_service_cls,
    proxy_service_cls,
) -> None:
    @app.route("/admin/auto-routes", methods=["GET", "PUT"])
    @login_required
    def admin_auto_routes():
        _require_admin(auth_service_cls)
        if request.method == "PUT":
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                raise APIError(
                    "Request body must be a JSON object",
                    status_code=400,
                )
            try:
                AutoRouteService.save_route(
                    payload.get("route_id"),
                    payload.get("candidates"),
                    app.config["API_BASE_URLS"],
                )
            except ValueError as error:
                raise APIError(str(error), status_code=400) from error
        return jsonify(_admin_payload(app, auth_service_cls))

    @app.route("/admin/auto-routes/catalog", methods=["POST"])
    @login_required
    def admin_auto_route_catalog():
        _require_admin(auth_service_cls)
        refresh_results = ProviderCatalogService.refresh_configured(
            app.config["API_BASE_URLS"],
            auth_service_cls,
            proxy_service_cls,
        )
        payload = _admin_payload(app, auth_service_cls)
        payload["catalog_refresh"] = refresh_results
        return jsonify(payload)
