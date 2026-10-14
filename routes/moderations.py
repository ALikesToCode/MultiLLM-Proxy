"""Standalone moderation routing, independent of generation enforcement."""

from dataclasses import replace

from flask import request

from error_handlers import APIError
from route_helpers import api_auth_required, request_body_limit
from routes.auto_routes import dispatch_auto_route
from routes.media_audio import (
    MediaRequest,
    Operation,
    dispatch_media_candidate,
    media_fail_over,
    validate_media_candidate,
)
from services.auto_route_service import AutoRouteService
from services.model_registry import ModelRegistry
from services.moderation_input import (
    MAX_MODERATION_BODY_BYTES,
    has_images,
    text_only_input,
    validate_moderation_input,
)

MODERATION = Operation("moderation", "auto:moderation", "v1/moderations",
                       frozenset({"openai", "navyai", "nanogpt"}), frozenset(), (3, 15))


def moderation_request(body):
    if not isinstance(body, dict) or set(body) - {"model", "input"}:
        raise APIError("Moderation accepts a JSON object with model and input", status_code=400)
    validate_moderation_input(body.get("input"))
    supplied_model = body.get("model")
    model = MODERATION.route if supplied_model in (None, "") else supplied_model
    if not isinstance(model, str):
        raise APIError("model must be a string", status_code=400)
    if ":" not in model:
        model = f"openai:{model}"
    return MediaRequest(MODERATION, model, {"input": body["input"]})


def validate_candidate(app, auth, media, candidate):
    validate_media_candidate(app, auth, media, candidate)
    provider, _ = ModelRegistry.parse_model_id(candidate)
    if provider == "navyai" and has_images(media.fields["input"]):
        raise APIError("NavyAI moderation accepts text only", status_code=400)


def dispatch_candidate(app, auth, metrics, proxy, media, candidate):
    provider, _ = ModelRegistry.parse_model_id(candidate)
    if provider == "navyai":
        media = replace(media, fields={"input": text_only_input(media.fields["input"])})
    return dispatch_media_candidate(app, auth, metrics, proxy, media, candidate)


def run_moderation(media, app, auth, metrics, proxy):
    def validate(candidate):
        validate_candidate(app, auth, media, candidate)

    if AutoRouteService.is_auto_route(media.model):
        return dispatch_auto_route({"model": media.model}, validate_candidate=validate,
            dispatch_candidate=lambda payload, candidate, decision: dispatch_candidate(
                app, auth, metrics, proxy, media, candidate), fail_over=media_fail_over)
    try:
        validate(media.model)
    except ValueError as error:
        raise APIError(str(error), status_code=400) from error
    return dispatch_candidate(app, auth, metrics, proxy, media, media.model)


def register_moderation_routes(app, csrf, auth, metrics, proxy):
    @app.route("/v1/moderations", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    @request_body_limit(lambda: MAX_MODERATION_BODY_BYTES)
    def moderations():
        return run_moderation(moderation_request(request.get_json(silent=True)), app, auth, metrics, proxy)
