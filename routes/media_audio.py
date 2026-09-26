"""Embeddings, speech and transcription on automatic routes or one provider:model.

`/v1/embeddings`, `/v1/audio/speech` and `/v1/audio/transcriptions` run on `auto:embed`,
`auto:tts` and `auto:stt` (the defaults when `model` is omitted) or on an explicit
`provider:model`. These calls are cheap but billable, so a route moves on only after a
definite refusal: a 4xx the provider sends before doing any work, a locally open
circuit, or a connection that never opened. A timeout, a dropped connection or a 5xx
stops the route. Requests from intelligence principals, or naming the model the
intelligence policy pins, keep the gateway's accounting (routes/intelligence_media.py).
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass

import requests
from flask import Response, request

from error_handlers import APIError
from providers.registry import get_adapter
from route_helpers import stream_upstream_response
from routes.auto_routes import AutoRouteCandidateUnavailable, dispatch_auto_route
from routes.provider_credentials import _add_credential_attempt_headers, _request_with_provider_token_rotation
from services import cloudflare_ai
from services.auto_route_service import AutoRouteService
from services.media_catalog import TRANSPORT_FAILURE_HEADER
from services.model_registry import ModelRegistry

MAX_EMBEDDING_INPUTS = 2048
MAX_EMBEDDING_BYTES = 2 * 1024 * 1024
MAX_SPEECH_CHARS = 4096
MAX_AUDIO_BYTES = 25 * 1024 * 1024
MAX_CLOUDFLARE_AUDIO_BYTES = 8 * 1024 * 1024
AUDIO_EXTENSIONS = frozenset({"flac", "m4a", "mp3", "mp4", "mpeg", "mpga", "oga", "ogg", "opus", "wav", "webm"})
SPEECH_FORMATS = ("mp3", "opus", "aac", "flac", "wav", "pcm")
# A refusal proves no work was done; anything else might have been billed.
REFUSAL_STATUSES = frozenset({400, 401, 402, 403, 404, 409, 413, 415, 422, 429})
_PRE_DISPATCH_STATUSES = frozenset({400, 401, 402, 403, 404, 409, 413, 422, 429, 503})


@dataclass(frozen=True)
class Operation:
    name: str
    route: str
    path: str
    providers: frozenset[str]
    cloudflare_models: frozenset[str]
    timeout: tuple[int, int]


OPERATIONS = {
    "embeddings": Operation("embeddings", "auto:embed", "v1/embeddings",
                            frozenset({"openai", "nanogpt", "navyai", "together", "gemini", "cloudflare"}),
                            frozenset({"@cf/baai/bge-m3", "@cf/baai/bge-large-en-v1.5", "@cf/baai/bge-base-en-v1.5"}),
                            (5, 120)),
    "speech": Operation("speech", "auto:tts", "v1/audio/speech",
                        frozenset({"openai", "nanogpt", "navyai", "together", "cloudflare"}),
                        frozenset({"@cf/deepgram/aura-2-en"}), (5, 180)),
    "transcriptions": Operation("transcriptions", "auto:stt", "v1/audio/transcriptions",
                                frozenset({"openai", "nanogpt", "navyai", "together", "cloudflare"}),
                                frozenset({"@cf/openai/whisper-large-v3-turbo"}), (5, 600)),
}
# Gemini serves OpenAI-compatible embeddings under its /openai prefix.
_UPSTREAM_PATHS = {("gemini", "embeddings"): "openai/embeddings"}


def media_fail_over(response: Response) -> bool:
    """Whether the next candidate may run without risking a second charge."""
    kind = response.headers.get(TRANSPORT_FAILURE_HEADER)
    if kind:
        return kind == "connect"
    if response.status_code in REFUSAL_STATUSES:
        return True
    return response.status_code == 503 and response.headers.get("X-MultiLLM-Circuit-State") in {"open", "half_open"}


@dataclass(frozen=True)
class MediaRequest:
    operation: Operation
    model: str
    fields: dict
    audio: bytes = b""
    filename: str = ""


def _embedding_inputs(value: object) -> int:
    if isinstance(value, str) and value:
        return 1
    if isinstance(value, list) and value:
        if all(type(token) is int and token >= 0 for token in value):
            return 1
        if all(isinstance(text, str) and text for text in value) or all(
                isinstance(tokens, list) and tokens and all(type(token) is int and token >= 0 for token in tokens)
                for tokens in value):
            return len(value)
    raise APIError("input must be a string, a list of strings or token arrays", status_code=400)


def parse_media_request(operation_name: str) -> MediaRequest:
    operation = OPERATIONS[operation_name]
    if operation_name == "transcriptions":
        if set(request.files) != {"file"} or len(request.files.getlist("file")) != 1:
            raise APIError("Send exactly one audio file as file", status_code=400)
        upload = request.files["file"]
        extension = (upload.filename or "").rsplit(".", 1)[-1].lower()
        if extension not in AUDIO_EXTENSIONS:
            raise APIError(f"file must be one of: {', '.join(sorted(AUDIO_EXTENSIONS))}", status_code=400)
        audio = upload.read(MAX_AUDIO_BYTES + 1)
        if not audio or len(audio) > MAX_AUDIO_BYTES:
            raise APIError("file must hold 1 byte to 25 MiB of audio", status_code=413 if audio else 400)
        fields = request.form.to_dict()
        if set(fields) - {"model", "language", "prompt", "response_format", "temperature"}:
            raise APIError("Transcriptions accept model, language, prompt, response_format and temperature",
                           status_code=400)
        if fields.get("response_format", "json") not in ("json", "text"):
            raise APIError("response_format must be json or text", status_code=400)
        return MediaRequest(operation, fields.pop("model", "") or operation.route, fields, audio, f"audio.{extension}")
    if (request.content_length or 0) > MAX_EMBEDDING_BYTES:
        raise APIError("The request body is too large", status_code=413)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise APIError("Request body must be a JSON object", status_code=400)
    fields = dict(body)
    model = fields.pop("model", None) or operation.route
    if not isinstance(model, str):
        raise APIError("model must be a string", status_code=400)
    if operation_name == "embeddings":
        if set(fields) - {"input", "dimensions", "encoding_format", "user"}:
            raise APIError("Embeddings accept model, input, dimensions, encoding_format and user", status_code=400)
        if _embedding_inputs(fields.get("input")) > MAX_EMBEDDING_INPUTS:
            raise APIError(f"input may hold at most {MAX_EMBEDDING_INPUTS} items", status_code=400)
        if fields.get("encoding_format", "float") not in ("float", "base64"):
            raise APIError("encoding_format must be float or base64", status_code=400)
        if "dimensions" in fields and (type(fields["dimensions"]) is not int or not 1 <= fields["dimensions"] <= 8192):
            raise APIError("dimensions must be an integer from 1 to 8192", status_code=400)
    else:
        if set(fields) - {"input", "voice", "response_format", "speed", "instructions"}:
            raise APIError("Speech accepts model, input, voice, response_format, speed and instructions", status_code=400)
        text = fields.get("input")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_SPEECH_CHARS:
            raise APIError(f"input must be 1 to {MAX_SPEECH_CHARS} characters", status_code=400)
        if fields.setdefault("response_format", "mp3") not in SPEECH_FORMATS:
            raise APIError(f"response_format must be one of: {', '.join(SPEECH_FORMATS)}", status_code=400)
    return MediaRequest(operation, model, fields)


def validate_media_candidate(app, auth_service_cls, media: MediaRequest, candidate: str) -> None:
    """Refuse, before sending anything, a candidate that cannot serve this request."""
    provider, provider_model = ModelRegistry.parse_model_id(candidate)
    operation = media.operation
    if provider not in operation.providers:
        raise APIError(f"{operation.name} is not supported for provider: {provider}", status_code=400)
    if ModelRegistry.get_model_status(candidate) == "disabled":
        raise APIError(f"Model is disabled: {candidate}", status_code=400)
    if provider == "cloudflare":
        if provider_model not in operation.cloudflare_models:
            raise APIError(f"{candidate} does not serve {operation.name}", status_code=400)
        if not cloudflare_ai.enabled():
            raise APIError("Cloudflare AI is not bound to this deployment", status_code=503)
        if operation.name == "embeddings" and (
                "dimensions" in media.fields or media.fields.get("encoding_format", "float") != "float"
                or not all(isinstance(text, str) for text in ([media.fields["input"]]
                                                               if isinstance(media.fields["input"], str)
                                                               else media.fields["input"]))):
            raise APIError(f"{candidate} takes text input only, without dimensions or base64", status_code=400)
        if operation.name == "transcriptions" and len(media.audio) > MAX_CLOUDFLARE_AUDIO_BYTES:
            raise APIError(f"{candidate} accepts at most 8 MiB of audio", status_code=413)
        return
    if get_adapter(provider, app.config["API_BASE_URLS"]) is None:
        raise APIError(f"Unsupported provider: {provider}", status_code=400)
    keys = auth_service_cls.get_api_keys(provider) if provider == "nanogpt" else [auth_service_cls.get_api_key(provider)]
    if not any(keys):
        raise APIError(f"No credential is configured for provider: {provider}", status_code=503)


def _cloudflare(media: MediaRequest, provider_model: str) -> Response:
    operation = media.operation
    if operation.name == "transcriptions":
        response = cloudflare_ai.run_audio(f"/{operation.path}", {
            "model": provider_model, "audio": base64.b64encode(media.audio).decode("ascii"),
            **{name: media.fields[name] for name in ("language", "prompt") if media.fields.get(name)}}, operation.timeout)
        if response.status_code == 200 and media.fields.get("response_format") == "text":
            text = (response.get_json(silent=True) or {}).get("text", "")
            return Response(text, content_type="text/plain; charset=utf-8")
        return response
    return cloudflare_ai.run_audio(f"/{operation.path}", {**media.fields, "model": provider_model}, operation.timeout)


def _body(media: MediaRequest, provider_model: str) -> tuple[bytes, str]:
    if media.operation.name == "transcriptions":
        prepared = requests.Request("POST", "https://placeholder.invalid",
                                    data={**media.fields, "model": provider_model},
                                    files={"file": (media.filename, media.audio, "application/octet-stream")}).prepare()
        return prepared.body, prepared.headers["Content-Type"]
    fields = dict(media.fields)
    if media.operation.name == "speech":
        # OpenAI-compatible speech APIs require a voice.
        fields.setdefault("voice", "alloy")
    return json.dumps({**fields, "model": provider_model}, separators=(",", ":")).encode("utf-8"), "application/json"


def dispatch_media_candidate(app, auth_service_cls, metrics_service_cls, proxy_service_cls, media: MediaRequest,
                             candidate: str) -> Response:
    provider, provider_model = ModelRegistry.parse_model_id(candidate)
    started, status = time.time(), 502
    try:
        if provider == "cloudflare":
            response = _cloudflare(media, provider_model)
            status = response.status_code
            return response
        body, content_type = _body(media, provider_model)
        path = _UPSTREAM_PATHS.get((provider, media.operation.name), media.operation.path)
        base = app.config["NANOGPT_STANDARD_BASE_URL"] if provider == "nanogpt" else app.config["API_BASE_URLS"][provider]

        def send(token: str):
            headers = proxy_service_cls.prepare_headers({"Content-Type": content_type}, provider, token, upstream_path=path)
            headers["Content-Type"] = content_type
            return proxy_service_cls.make_request(method="POST", url=f"{base.rstrip('/')}/{path}", headers=headers,
                                                  params={}, data=body, api_provider=provider, use_cache=False,
                                                  timeout_override=media.operation.timeout, force_raw_passthrough=True)

        upstream, attempts = _request_with_provider_token_rotation(app, auth_service_cls, proxy_service_cls, provider, send)
        status = upstream.status_code
        downstream = upstream if isinstance(upstream, Response) else stream_upstream_response(upstream)
        failure = getattr(upstream, "multillm_transport_failure", None)
        if failure:
            downstream.headers[TRANSPORT_FAILURE_HEADER] = failure
        return _add_credential_attempt_headers(downstream, provider, attempts)
    except APIError as error:
        status = error.status_code
        raise
    finally:
        metrics_service_cls.get_instance().track_request(provider=provider, status_code=status,
                                                         response_time=(time.time() - started) * 1000)


def dispatch_media_route(operation_name: str, app, auth_service_cls, metrics_service_cls, proxy_service_cls) -> Response:
    """One embeddings, speech or transcription request on a route or an explicit model."""
    media = parse_media_request(operation_name)

    def validate(candidate: str) -> None:
        validate_media_candidate(app, auth_service_cls, media, candidate)

    def dispatch(candidate: str) -> Response:
        try:
            return dispatch_media_candidate(app, auth_service_cls, metrics_service_cls, proxy_service_cls, media, candidate)
        except APIError as error:
            if error.status_code in _PRE_DISPATCH_STATUSES:
                raise AutoRouteCandidateUnavailable(error.message) from error
            raise

    if AutoRouteService.is_auto_route(media.model):
        return dispatch_auto_route({"model": media.model}, validate_candidate=validate,
                                   dispatch_candidate=lambda payload, candidate, decision: dispatch(candidate),
                                   fail_over=media_fail_over)
    try:
        validate(media.model)
    except ValueError as error:
        raise APIError(str(error), status_code=400) from error
    return dispatch_media_candidate(app, auth_service_cls, metrics_service_cls, proxy_service_cls, media, media.model)
