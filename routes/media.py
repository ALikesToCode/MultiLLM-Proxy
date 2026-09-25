"""Image batches, asynchronous video jobs and media provider status."""

from __future__ import annotations

import time

from flask import g, jsonify, url_for

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_auth_required, api_authenticate_only
from routes.auto_routes import AutoRouteCandidateUnavailable, dispatch_auto_route
from routes.media_images import image_fail_over, run_image_batch
from routes.unified import _validate_image_candidate, dispatch_unified_image_generation
from services import cloudflare_ai, video_generation
from services.auto_route_service import AutoRouteService
from services.media_catalog import prepare_image_payload
from services.model_registry import ModelRegistry
from services.resilience_service import ResilienceService

DEFAULT_VIDEO_ROUTE = "auto:video"
PROBE_PROMPT = "A small red circle centered on a plain white background"
_PRE_GENERATION_STATUSES = frozenset({400, 401, 402, 403, 404, 409, 422, 429, 503})


def _owner() -> str:
    user = getattr(g, "authenticated_user", None) or {}
    owner = user.get("username") or user.get("id")
    if not owner:
        raise APIError("Authentication required", status_code=401)
    return str(owner)


def _is_media_route(route) -> bool:
    return "image" in route.id or "video" in route.id


def register_media_routes(app, csrf, auth_service_cls, metrics_service_cls, proxy_service_cls) -> None:
    def generate_image(body: dict):
        return dispatch_unified_image_generation(app, auth_service_cls, metrics_service_cls, proxy_service_cls, body)

    def video_credentials(provider: str) -> tuple[str | None, str]:
        return auth_service_cls.get_api_key(provider), app.config["API_BASE_URLS"].get(provider, "")

    def validate_video_candidate(candidate: str) -> None:
        provider, _ = ModelRegistry.parse_model_id(candidate)
        if provider not in video_generation.VIDEO_PROVIDERS:
            raise APIError(f"Video generation is not supported for provider: {provider}", status_code=400)
        if ModelRegistry.get_model_status(candidate) == "disabled":
            raise APIError(f"Model is disabled: {candidate}", status_code=400)
        configured = cloudflare_ai.enabled() if provider == "cloudflare" else bool(auth_service_cls.get_api_key(provider))
        if not configured:
            raise APIError(f"No credential is configured for provider: {provider}", status_code=503)

    def candidate_status(candidate: str, validate) -> dict:
        provider, _ = ModelRegistry.parse_model_id(candidate)
        entry = {"model": candidate, "provider": provider}
        try:
            validate(candidate)
            entry["available"] = True
        except (APIError, ValueError) as error:
            entry.update(available=False, reason=getattr(error, "message", str(error)))
        circuit = ResilienceService.snapshot(provider)
        entry["circuit"] = circuit["state"]
        if circuit["last_status"] is not None:
            entry["last_status"] = circuit["last_status"]
        return entry

    def validate_image_candidate(candidate: str) -> None:
        _validate_image_candidate(app, auth_service_cls, proxy_service_cls, candidate)

    @app.route("/v1/images/batch", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def image_batch():
        return jsonify(run_image_batch(json_object_body(), generate_image))

    @app.route("/v1/videos", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def create_video():
        body = json_object_body()
        video_request = video_generation.parse_video_request(body)
        model = body.get("model") or DEFAULT_VIDEO_ROUTE
        owner = _owner()

        def create(candidate: str):
            provider, provider_model = ModelRegistry.parse_model_id(candidate)
            key, base_url = video_credentials(provider)
            try:
                return video_generation.create_job(provider, provider_model, video_request, key, base_url, owner)
            except APIError as error:
                if error.status_code in _PRE_GENERATION_STATUSES:
                    raise AutoRouteCandidateUnavailable(error.message) from error
                raise

        if AutoRouteService.is_auto_route(model):
            # Like images, any provider refusal means no job exists; a job whose
            # creation outcome is unknown is never started again elsewhere.
            return dispatch_auto_route({"model": model}, validate_candidate=validate_video_candidate,
                                       dispatch_candidate=lambda payload, candidate, decision: create(candidate),
                                       fail_over=image_fail_over)
        validate_video_candidate(model)
        try:
            return create(model)
        except AutoRouteCandidateUnavailable as error:
            raise APIError(error.message, status_code=400) from error

    @app.route("/v1/videos/<job_id>", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def video_status(job_id: str):
        job = video_generation.read_job_id(job_id, _owner())
        key, base_url = video_credentials(job["p"])
        status = video_generation.job_status(job, job_id, key, base_url)
        if status["status"] == "completed":
            status["content_url"] = url_for("video_content", job_id=job_id, _external=True)
        return jsonify(status)

    @app.route("/v1/videos/<job_id>/content", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def video_content(job_id: str):
        job = video_generation.read_job_id(job_id, _owner())
        key, base_url = video_credentials(job["p"])
        url, headers = video_generation.content_source(job, key, base_url)
        return video_generation.stream_content(url, headers)

    @app.route("/v1/media/providers", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def media_providers():
        """Which media route candidates can run now, without generating anything."""
        routes = [route for route in AutoRouteService.list_routes() if _is_media_route(route)]
        return jsonify({"cloudflare_ai": cloudflare_ai.enabled(), "routes": [
            {"id": route.id, "kind": "video" if "video" in route.id else "image", "candidates": [
                candidate_status(candidate, validate_video_candidate if "video" in route.id else validate_image_candidate)
                for candidate in route.candidates]}
            for route in routes]})

    @app.route("/v1/media/probe", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only(required_scope="admin")
    def media_probe():
        """Generate one small, low-quality image on every candidate of an image route.

        This spends money on each available provider (about $0.01 to $0.04 per image), so it
        is limited to administrators and never runs automatically.
        """
        body = json_object_body()
        route_id = body.get("route", "auto:image")
        route = AutoRouteService.get_route(route_id)
        if route is None or "image" not in route.id:
            raise APIError("Name an automatic image route", status_code=400)
        report = []
        for candidate in route.candidates:
            entry = candidate_status(candidate, validate_image_candidate)
            if entry["available"]:
                started = time.monotonic()
                provider, provider_model = ModelRegistry.parse_model_id(candidate)
                probe = prepare_image_payload(provider, provider_model, {"model": candidate, "prompt": PROBE_PROMPT,
                                                                         "size": "1024x1024", "quality": "low", "n": 1})
                try:
                    response = generate_image(probe)
                    data = response.get_json(silent=True) or {}
                    response.close()
                    entry.update(status=response.status_code, working=response.status_code < 400 and bool(data.get("data")))
                    if not entry["working"]:
                        error = data.get("error")
                        entry["error"] = (error.get("message") if isinstance(error, dict) else str(error or ""))[:300]
                except APIError as error:
                    entry.update(status=error.status_code, working=False, error=error.message[:300])
                entry["seconds"] = round(time.monotonic() - started, 1)
            report.append(entry)
        return jsonify({"route": route.id, "candidates": report,
                        "working": [entry["model"] for entry in report if entry.get("working")]})
