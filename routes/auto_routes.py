import logging
import os
import time
from collections.abc import Callable

from flask import Response, g, has_request_context, jsonify, request

from error_handlers import APIError
from services.model_cooldown import ModelCooldownCapacity, ModelCooldownExhausted
from providers.registry import get_registry
from services import cloudflare_ai
from services import canary_traffic
from services.auto_route_service import AutoRoute, AutoRouteService
from services.media_catalog import (
    TRANSPORT_FAILURE_HEADER,
    image_profile,
    is_speech_or_embedding_model,
    is_video_model,
)
from services.model_catalog_service import build_model_catalog
from services.model_registry import ModelRegistry
from services.provider_catalog_refresh import refresh_model_catalogs
from services.provider_catalog_service import (
    PROVIDER_CATALOG_SPECS,
    ProviderCatalogService,
)
from services.resilience_service import ResilienceService
from services.route_health import RouteHealth, ordering_settings
from services.stream_preflight import preflight_chat_stream
from services.generation_deadline import (
    GenerationDeadlineExceeded, check_deadline, check_response_deadline,
)

# Payment-required responses mean this candidate cannot serve the request with
# its current credentials. Explicit auto routes may safely try the next
# provider because the rejected candidate did not perform a generation.
AUTO_ROUTE_FALLBACK_STATUS_CODES = frozenset({401, 402, 403, 404, 429})
# Chat also moves on after these upstream statuses: they arrive before any output is
# forwarded, so the caller has received nothing. 504 is left out because a gateway
# timeout may hide a generation that is still running and billed.
CHAT_FAILOVER_SERVER_STATUS_CODES = frozenset({500, 502, 503})
_MAX_REASONS_HEADER_LENGTH = 1024
logger = logging.getLogger(__name__)


class AutoRouteCandidateUnavailable(APIError):
    """Signal a pre-generation candidate failure that is safe to fail over."""

    def __init__(self, message: str):
        super().__init__(message, status_code=503)


def _circuit_is_open(response: Response) -> bool:
    return response.status_code == 503 and response.headers.get(
        "X-MultiLLM-Circuit-State"
    ) in {"open", "half_open"}


def _is_fallback_response(response: Response) -> bool:
    if response.status_code in AUTO_ROUTE_FALLBACK_STATUS_CODES:
        return True
    return _circuit_is_open(response)


def chat_fail_over(response: Response) -> bool:
    """Whether the next chat candidate may run without repeating a generation.

    A definite refusal, a 500, 502 or 503 from the upstream, or a connection that was
    never established. A timeout, a dropped connection, a 504 and anything after a
    successful status (including a started stream) stay with the caller.
    """
    if _is_fallback_response(response):
        return True
    kind = response.headers.get(TRANSPORT_FAILURE_HEADER)
    if kind:
        return kind == "connect"
    return response.status_code in CHAT_FAILOVER_SERVER_STATUS_CODES


def mark_transport_failure(downstream: Response, upstream) -> Response:
    """Carry a local transport failure (connect, timeout, interrupted) onto the response."""
    kind = getattr(upstream, "multillm_transport_failure", None)
    if kind:
        downstream.headers[TRANSPORT_FAILURE_HEADER] = kind
    return downstream


def attempt_outcome(response: Response) -> tuple[bool | None, str]:
    """(success, reason) of one attempt for route health; None when the request was at fault."""
    kind = response.headers.get(TRANSPORT_FAILURE_HEADER)
    if kind:
        return False, kind
    status = response.status_code
    if status < 400:
        return True, "ok"
    if _circuit_is_open(response):
        # Answered locally; the open circuit already demotes the candidate.
        return None, "circuit_open"
    if status in AUTO_ROUTE_FALLBACK_STATUS_CODES or status >= 500:
        return False, f"http_{status}"
    return None, f"http_{status}"


def _buffer_failure(response: Response) -> Response:
    body = response.get_data()
    status_code = response.status_code
    headers = dict(response.headers)
    response.close()
    return Response(body, status=status_code, headers=headers)


def _route_decision(priority: int, position: int) -> str:
    """Primary when the configured first candidate answers first; health when reordering did."""
    if position == 0:
        return "auto-primary" if priority == 0 else "auto-health"
    return "auto-failover"


def _circuit_state(provider: str) -> str:
    return ResilienceService.snapshot(provider)["state"]


def _decorate_response(
    response: Response,
    route: AutoRoute,
    selected_model: str,
    selected_priority: int,
    attempts: int,
    *,
    route_decision: str | None = None,
    ordering: str = "priority",
    failures: list[tuple[str, str]] | None = None,
    canary: canary_traffic.CanaryAssignment | None = None,
) -> Response:
    selected_provider, _ = ModelRegistry.parse_model_id(selected_model)
    if route_decision is None:
        route_decision = "auto-primary" if selected_priority == 0 else "auto-failover"
    response.headers["X-MultiLLM-Auto-Route"] = route.id
    response.headers["X-MultiLLM-Auto-Selected-Model"] = selected_model
    response.headers["X-MultiLLM-Auto-Attempts"] = str(attempts)
    response.headers["X-MultiLLM-Auto-Selected-Priority"] = str(selected_priority + 1)
    response.headers["X-MultiLLM-Auto-Ordering"] = ordering
    if failures:
        reasons = ", ".join(f"{candidate}={reason}" for candidate, reason in failures)
        if len(reasons) > _MAX_REASONS_HEADER_LENGTH:
            reasons = reasons[:_MAX_REASONS_HEADER_LENGTH].rsplit(", ", 1)[0]
        response.headers["X-MultiLLM-Auto-Failover-Reasons"] = reasons
    if has_request_context():
        g.multillm_provider = selected_provider
        g.multillm_model = selected_model
        g.multillm_route_decision = route_decision
    if canary is not None:
        canary.decorate(response)
    return response


def dispatch_auto_route(
    payload: dict,
    *,
    validate_candidate: Callable[[str], None],
    dispatch_candidate: Callable[[dict, str, str], Response],
    fail_over: Callable[[Response], bool] = _is_fallback_response,
) -> Response:
    """Run an explicit priority list through injected validation and transport.

    By default only a refusal that proves the candidate generated nothing moves on.
    Chat routes pass chat_fail_over and image routes routes.media_images.image_fail_over.
    Each attempt's outcome and time to response feed route health, and a route set to
    health ordering tries its candidates in the order RouteHealth.order returns.
    """
    check_deadline()
    route = AutoRouteService.get_route(payload.get("model"))
    if route is None:
        raise APIError(
            f"Auto route not found: {payload.get('model')}",
            status_code=404,
        )

    canary = canary_traffic.prepare_request(route, payload)
    candidates = canary.dispatch_order if canary is not None else route.candidates
    order = RouteHealth.order(route.id, candidates, circuit_state=_circuit_state)
    if canary is not None:
        canary.observe(order.candidates)
    priorities = {candidate: index for index, candidate in enumerate(route.candidates)}
    attempts = 0
    failures: list[tuple[str, str]] = []
    last_failure: Response | None = None
    last_model = ""
    last_priority = 0
    last_decision = "auto-failover"
    for position, candidate in enumerate(order.candidates):
        check_deadline()
        priority = priorities[candidate]
        try:
            validate_candidate(candidate)
            check_deadline()
        except (ModelCooldownExhausted, ModelCooldownCapacity, GenerationDeadlineExceeded):
            raise
        except (APIError, ValueError) as error:
            logger.info(
                "Skipping unavailable auto route candidate %s (%s)",
                candidate,
                type(error).__name__,
            )
            failures.append((candidate, "skipped"))
            if canary is not None:
                g.multillm_canary["eligible_order"] = [model for model in g.multillm_canary["eligible_order"]
                                                      if model != candidate]
            continue

        attempts += 1
        candidate_payload = dict(payload)
        candidate_payload["model"] = candidate
        route_decision = _route_decision(priority, position)
        started = time.monotonic()
        try:
            response = dispatch_candidate(
                candidate_payload,
                candidate,
                route_decision,
            )
            check_response_deadline(response)
        except AutoRouteCandidateUnavailable as error:
            logger.info(
                "Skipping auto route candidate %s before generation (%s)",
                candidate,
                type(error).__name__,
            )
            RouteHealth.record(candidate, ok=False, outcome="unavailable")
            failures.append((candidate, "unavailable"))
            continue
        except Exception:
            RouteHealth.record(candidate, ok=False, outcome="error")
            raise
        preflight_failed = False
        preflight_outcome = ""
        if (
            fail_over is chat_fail_over
            and has_request_context()
            and request.method == "POST"
            and request.path == "/v1/chat/completions"
            and payload.get("stream") is True
            and os.environ.get("MULTILLM_STREAM_PREFLIGHT", "off").strip().lower() == "strict"
        ):
            preflight = preflight_chat_stream(response)
            response = preflight.response
            check_response_deadline(response)
            preflight_failed = preflight.outcome not in {"skipped", "validated"}
            preflight_outcome = preflight.outcome
        ok, reason = attempt_outcome(response)
        if preflight_failed:
            ok, reason = False, preflight_outcome
        if ok is not None:
            RouteHealth.record(
                candidate,
                ok=ok,
                outcome=reason,
                latency_ms=(time.monotonic() - started) * 1000 if ok else None,
                status=response.status_code,
            )
        # A local preflight failure does not prove the provider generated nothing.
        if preflight_failed or not fail_over(response):
            if last_failure is not None:
                last_failure.close()
            return _decorate_response(
                response,
                route,
                candidate,
                priority,
                attempts,
                route_decision=route_decision,
                ordering=order.mode,
                failures=failures,
                canary=canary,
            )

        logger.info("Auto route %s moves past %s (%s)", route.id, candidate, reason)
        failures.append((candidate, reason))
        if last_failure is not None:
            last_failure.close()
        last_failure = _buffer_failure(response)
        last_model = candidate
        last_priority = priority
        last_decision = route_decision

    if last_failure is not None:
        return _decorate_response(
            last_failure,
            route,
            last_model,
            last_priority,
            attempts,
            route_decision=last_decision,
            ordering=order.mode,
            failures=[failure for failure in failures if failure[0] != last_model],
            canary=canary,
        )
    raise APIError(
        f"No configured provider is available for auto route: {route.id}",
        status_code=503,
    )


def dispatch_auto_route_chat_completion(
    payload: dict,
    *,
    validate_candidate: Callable[[str], None],
    dispatch_candidate: Callable[[dict, str, str], Response],
) -> Response:
    """Chat routes: fail over on refusals and on 5xx or connect failures before any output."""
    return dispatch_auto_route(
        payload,
        validate_candidate=validate_candidate,
        dispatch_candidate=dispatch_candidate,
        fail_over=chat_fail_over,
    )


def _candidate_capabilities(candidate: str, catalog_capabilities: dict) -> dict:
    # Provider capabilities describe the account; media models only generate media.
    provider, provider_model = ModelRegistry.parse_model_id(candidate)
    if image_profile(provider, provider_model) is not None:
        return {"supports_chat": False, "supports_images": True, "supports_video": False}
    if is_video_model(provider_model):
        return {"supports_chat": False, "supports_images": False, "supports_video": True}
    if is_speech_or_embedding_model(provider_model):
        return {"supports_chat": False, "supports_images": False, "supports_video": False}
    return catalog_capabilities


def _route_capabilities(route: AutoRoute, catalog: list[dict]) -> dict[str, bool]:
    """A route can do what at least one of its candidates can do."""
    by_id = {model["id"]: model.get("capabilities") or {} for model in catalog}
    candidates = [_candidate_capabilities(candidate, by_id.get(candidate, {})) for candidate in route.candidates]
    return {
        name: any(bool(capabilities.get(name)) for capabilities in candidates)
        for name in ("supports_chat", "supports_images", "supports_video")
    }


def openai_auto_route_models(catalog: list[dict] | None = None) -> list[dict]:
    models = []
    for route in AutoRouteService.list_routes():
        model = {
            "id": route.id,
            "object": "model",
            "created": 0,
            "owned_by": "multillm-auto",
            "status": "available",
        }
        if catalog is not None:
            model["capabilities"] = _route_capabilities(route, catalog)
        models.append(model)
    return models


def _provider_is_configured(auth_service_cls, provider: str) -> bool:
    if provider == "cloudflare":
        return cloudflare_ai.enabled()
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
            "configured": configured_by_provider.get(model["provider"], False),
        }
        for model in model_catalog
    ]
    model_catalog_by_id = {model["id"]: model for model in model_catalog}

    routes = []
    settings = ordering_settings()
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
                    "configured": configured_by_provider.get(provider, False),
                    "status": model_catalog_by_id.get(model_id, {}).get(
                        "status",
                        "unknown",
                    ),
                    "health": RouteHealth.summary(model_id),
                }
            )
        routes.append(
            {
                "id": route.id,
                "candidates": candidates,
                "updated_at": route.updated_at,
                "ordering": settings.mode_for(route.id),
                **({"canary": route.canary.as_dict()} if route.canary.enabled else {}),
            }
        )
    return {
        "routes": routes,
        "providers": providers,
        "model_catalog": model_catalog,
        "fallback_statuses": sorted(AUTO_ROUTE_FALLBACK_STATUS_CODES),
        "chat_fallback_server_statuses": sorted(CHAT_FAILOVER_SERVER_STATUS_CODES),
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
    # Preserve cohort visibility when existing policy guards raise an API error.
    app.after_request(canary_traffic.decorate_current_response)

    @app.route("/admin/auto-routes", methods=["GET", "PUT"])
    @login_required
    def admin_auto_routes():
        _require_admin(auth_service_cls)
        refresh_model_catalogs(app, auth_service_cls, proxy_service_cls)
        if request.method == "PUT":
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                raise APIError(
                    "Request body must be a JSON object",
                    status_code=400,
                )
            try:
                canary_options = {"canary": payload["canary"]} if "canary" in payload else {}
                if "expected_updated_at" in payload:
                    canary_options["expected_updated_at"] = payload["expected_updated_at"]
                if "current_revision" in payload:
                    canary_options["current_revision"] = payload["current_revision"]
                AutoRouteService.save_route(
                    payload.get("route_id"),
                    payload.get("candidates"),
                    app.config["API_BASE_URLS"],
                    **canary_options,
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
            supplemental_base_urls={
                "opencode": app.config["OPENCODE_ZEN_BASE_URL"],
            },
        )
        payload = _admin_payload(app, auth_service_cls)
        payload["catalog_refresh"] = refresh_results
        return jsonify(payload)
