"""Image batches and edits, asynchronous video jobs, stored media and provider status."""

from __future__ import annotations

import hashlib
import time

from flask import g, jsonify, request, url_for

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_auth_required, api_authenticate_only
from routes.auto_routes import AutoRouteCandidateUnavailable, dispatch_auto_route
from routes.media_edits import dispatch_image_edit, parse_json_edit, parse_multipart_edit
from routes.media_batches import principal_user, read_request_principal, register_media_batch_routes
from routes.media_files import register_media_file_routes, stream_stored_file, unavailable
from routes.media_images import image_fail_over, run_image_batch
from routes.unified import _validate_image_candidate, dispatch_unified_image_generation
from services import cloudflare_ai, media_jobs, media_storage, video_generation
from services.auto_route_service import AutoRouteService
from services.media_catalog import prepare_image_payload
from services.media_signing import issue_principal, webhook_secret
from services.media_urls import public_https_url
from services.model_registry import ModelRegistry
from services.resilience_service import ResilienceService

DEFAULT_VIDEO_ROUTE = "auto:video"
PROBE_PROMPT = "A small red circle centered on a plain white background"
_PRE_GENERATION_STATUSES = frozenset({400, 401, 402, 403, 404, 409, 422, 429, 503})
VIDEO_WATCH_TTL_SECONDS = 7 * 86400


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

    def stored_video(job: dict, job_id: str, owner: str) -> str | None:
        """With R2 bound, copy a finished video there once; its file ID, or None."""
        if not media_storage.enabled():
            return None
        file_id = media_storage.video_file_id(job_id)
        try:
            if media_storage.stat(file_id) is None:
                key, base_url = video_credentials(job["p"])
                url, headers = video_generation.content_source(job, key, base_url)
                if not url.startswith("https://") or media_storage.store_video(
                        file_id, url, headers, owner=owner, model=f"{job['p']}:{job['m']}") is None:
                    return None
            return file_id
        except (APIError, media_storage.StorageError):
            # The provider's copy still serves /content; storing is retried on the next poll.
            return None

    def watch_video(response, webhook_url: str, owner: str):
        """Register a created job with the Workflow that posts its webhook when it ends."""
        job = response.get_json(silent=True) if response.status_code == 200 else None
        if not isinstance(job, dict) or not isinstance(job.get("id"), str):
            return response
        digest = hashlib.sha256(job["id"].encode("utf-8")).hexdigest()
        watch_id = f"vwatch_{digest[:32]}"
        try:
            media_jobs.call("watch_video", id=watch_id, owner=owner, webhook_url=webhook_url, request_digest=digest,
                            principal=issue_principal("video", watch_id, owner, VIDEO_WATCH_TTL_SECONDS),
                            metadata={"job_id": job["id"], "model": job.get("model")})
            job["webhook"] = {"url": webhook_url, "status": "pending", "secret": webhook_secret(owner)}
        except media_jobs.MediaJobError:
            # The job exists and may be billed; only the notification is missing.
            job["webhook"] = {"url": webhook_url, "status": "unavailable"}
        rewritten = jsonify(job)
        for name, value in response.headers.items():
            if name.lower() not in ("content-length", "content-type"):
                rewritten.headers[name] = value
        response.close()
        return rewritten

    register_media_file_routes(app, csrf)
    register_media_batch_routes(app, csrf, auth_service_cls, validate_image_candidate, generate_image)

    @app.route("/v1/images/batch", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def image_batch():
        def persist(images: list, item: dict, model: str) -> list:
            if not media_storage.enabled():
                return images
            stored, _ = media_storage.store_image_entries(images, owner=_owner(), model=model,
                                                          want_url=item.get("response_format") == "url")
            return stored

        return jsonify(run_image_batch(json_object_body(), generate_image, persist))

    @app.route("/v1/images/edits", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def image_edits():
        if request.mimetype == "multipart/form-data":
            payload, inputs = parse_multipart_edit()
        else:
            payload, inputs = parse_json_edit(json_object_body())
        return media_storage.persist_image_response(
            dispatch_image_edit(app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload, inputs), payload)

    @app.route("/v1/videos", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def create_video():
        body = json_object_body()
        video_request = video_generation.parse_video_request(body)
        model = body.get("model") or DEFAULT_VIDEO_ROUTE
        owner = _owner()
        webhook_url = body.get("webhook_url")
        if webhook_url is not None:
            webhook_url = public_https_url(webhook_url, "webhook_url")
            if not media_jobs.enabled():
                return unavailable("webhooks_not_configured", "Video webhooks need the MEDIA_JOBS Workflow and D1 "
                                   "on the Worker; see docs/media-storage.md.")

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
            response = dispatch_auto_route({"model": model}, validate_candidate=validate_video_candidate,
                                           dispatch_candidate=lambda payload, candidate, decision: create(candidate),
                                           fail_over=image_fail_over)
        else:
            validate_video_candidate(model)
            try:
                response = create(model)
            except AutoRouteCandidateUnavailable as error:
                raise APIError(error.message, status_code=400) from error
        return watch_video(response, webhook_url, owner) if webhook_url else response

    @app.route("/internal/media/video-status", methods=["POST"])
    @csrf.exempt
    def media_video_status():
        """A video job's state for the Workflow that watches it (the Worker never exposes this path)."""
        claims = read_request_principal("video")
        body = request.get_json(silent=True)
        job_id = body.get("job_id") if isinstance(body, dict) else None
        if (not isinstance(job_id, str) or body.get("watch_id") != claims["s"]
                or f"vwatch_{hashlib.sha256(job_id.encode('utf-8')).hexdigest()[:32]}" != claims["s"]):
            raise APIError("Invalid video watch", status_code=400)
        try:
            user = principal_user(auth_service_cls, claims["o"])
        except APIError:
            response = jsonify({"retry": True})
            response.status_code = 503
            return response
        if user is None:
            raise APIError("The job owner's account no longer exists", status_code=403)
        g.authenticated_user = user
        job = video_generation.read_job_id(job_id, claims["o"])
        key, base_url = video_credentials(job["p"])
        status = video_generation.job_status(job, job_id, key, base_url)
        reply = {"status": status["status"], "model": status.get("model")}
        if status.get("error"):
            reply["error"] = status["error"]
        if status["status"] == "completed":
            reply["file_id"] = stored_video(job, job_id, claims["o"])
        return jsonify(reply)

    @app.route("/v1/videos/<job_id>", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def video_status(job_id: str):
        job = video_generation.read_job_id(job_id, _owner())
        key, base_url = video_credentials(job["p"])
        status = video_generation.job_status(job, job_id, key, base_url)
        if status["status"] == "completed":
            file_id = stored_video(job, job_id, _owner())
            if file_id:
                status.update(file_id=file_id, content_url=media_storage.file_url(file_id))
            else:
                status["content_url"] = url_for("video_content", job_id=job_id, _external=True)
        return jsonify(status)

    @app.route("/v1/videos/<job_id>/content", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def video_content(job_id: str):
        job = video_generation.read_job_id(job_id, _owner())
        if media_storage.enabled():
            file_id = media_storage.video_file_id(job_id)
            try:
                if media_storage.stat(file_id) is not None:
                    return stream_stored_file(file_id, "private, no-store")
            except media_storage.StorageError:
                pass
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
