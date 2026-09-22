"""Authenticated, pinned audio and embedding operations with no submission replay."""

import json
import math
import re
import time

import requests
from flask import Response, g, request

from error_handlers import get_request_id
from route_helpers import api_authenticate_only
from routes.auto_routes import _is_fallback_response
from routes.intelligence import error_response, load_policy, reject_idempotency
from services.intelligence_cancellation import CallerCancellation
from services.intelligence_contract import GatewayError
from services.intelligence_gateway import rejection
from services.intelligence_output import decode_completion
from services.intelligence_policy import eligible
from services.intelligence_store import IntelligenceStore
from services.intelligence_transport import IntelligenceTransport

JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
AUDIO_TYPES = {
    "audio/mpeg",
    "audio/mp3",
    "audio/wav",
    "audio/x-wav",
    "audio/ogg",
    "audio/flac",
    "audio/aac",
    "audio/opus",
    "application/octet-stream",
}


def _embedding_count(value):
    if isinstance(value, str) and value:
        return 1
    if not isinstance(value, list) or not value:
        raise ValueError("Embedding input is required")
    if all(type(token) is int and token >= 0 for token in value):
        return 1
    if all(isinstance(text, str) and text for text in value):
        return len(value)
    if all(
        isinstance(tokens, list)
        and tokens
        and all(type(token) is int and token >= 0 for token in tokens)
        for tokens in value
    ):
        return len(value)
    raise ValueError("Invalid embedding input")


def _payload(operation, settings):
    pinned = settings["candidate"]["model"]
    if operation == "transcriptions":
        if set(request.form) - {
            "model",
            "language",
            "prompt",
            "response_format",
            "temperature",
        }:
            raise ValueError("Unsupported transcription fields")
        if (
            request.form.get("model") != pinned
            or request.form.get("response_format", "json") != "json"
        ):
            raise ValueError("Transcription model and JSON format are pinned")
        if len(request.files.getlist("file")) != 1 or set(request.files) != {"file"}:
            raise ValueError("A single audio file is required")
        upload = request.files["file"]
        audio = upload.read(settings["max_input_bytes"] + 1)
        input_bytes = len(audio) + sum(
            len(value.encode()) for value in request.form.values()
        )
        if not audio or input_bytes > settings["max_input_bytes"]:
            raise GatewayError(
                "request_too_large",
                "The audio input is empty or exceeds the configured size limit.",
                413,
            )
        fields = request.form.to_dict()
        fields["model"] = pinned.split(":", 1)[1]
        fields["response_format"] = "json"
        suffix = (upload.filename or "").rsplit(".", 1)[-1].lower()
        if suffix not in {
            "wav",
            "mp3",
            "m4a",
            "webm",
            "mp4",
            "ogg",
            "flac",
            "mpeg",
            "mpga",
        }:
            raise ValueError("Unsupported audio file extension")
        prepared = requests.Request(
            "POST",
            "https://placeholder.invalid",
            data=fields,
            files={"file": (f"audio.{suffix}", audio, "application/octet-stream")},
        ).prepare()
        return {}, prepared.body, prepared.headers["Content-Type"]
    body = request.get_json(silent=True)
    fields = (
        {"model", "input", "voice", "response_format", "speed", "instructions"}
        if operation == "speech"
        else {"model", "input", "dimensions", "encoding_format", "user"}
    )
    if not isinstance(body, dict) or set(body) - fields or body.get("model") != pinned:
        raise ValueError("A pinned model is required")
    if len(json.dumps(body).encode()) > settings["max_input_bytes"]:
        raise GatewayError(
            "request_too_large", "The input exceeds the configured size limit.", 413
        )
    body = dict(body)
    if operation == "speech":
        if not isinstance(body.get("input"), str) or not body["input"].strip():
            raise ValueError("Speech requires text")
        if body.get("voice", settings["voice"]) != settings["voice"]:
            raise ValueError("Voice does not match the configured voice")
        body["voice"] = settings["voice"]
        if body.get("response_format", "mp3") not in {
            "mp3",
            "opus",
            "aac",
            "flac",
            "wav",
            "pcm",
        }:
            raise ValueError("Unsupported speech format")
    else:
        if (
            body.get("dimensions", settings["dimensions"]) != settings["dimensions"]
            or body.get("encoding_format", "float") != "float"
        ):
            raise ValueError("Embedding dimension and encoding are pinned")
        body["dimensions"] = settings["dimensions"]
        _embedding_count(body.get("input"))
    return body, None, None


def _embedding_result(payload, settings, submitted):
    data = payload.get("data")
    expected = _embedding_count(submitted["input"])
    if not isinstance(data, list) or len(data) != expected:
        raise ValueError("Missing embedding vectors")
    vectors = {}
    for item in data:
        vector = item.get("embedding") if isinstance(item, dict) else None
        index = item.get("index") if isinstance(item, dict) else None
        if (
            type(index) is not int
            or not 0 <= index < expected
            or index in vectors
            or not isinstance(vector, list)
            or len(vector) != settings["dimensions"]
            or any(type(v) not in (int, float) or not math.isfinite(v) for v in vector)
        ):
            raise ValueError("Embedding dimensions or indexes do not match")
        vectors[index] = {"object": "embedding", "index": index, "embedding": vector}
    return Response(
        json.dumps(
            {
                "object": "list",
                "model": settings["candidate"]["model"],
                "data": [vectors[index] for index in range(expected)],
            }
        ),
        content_type="application/json",
    )


def _result(operation, raw, head, settings, submitted):
    if head.status_code == 202:
        payload = decode_completion(raw)
        job_id = payload.get("id", payload.get("task_id"))
        status = payload.get("status", "accepted")
        if (
            not isinstance(job_id, str)
            or not JOB_ID.fullmatch(job_id)
            or status not in {"accepted", "pending", "queued", "processing"}
        ):
            raise GatewayError(
                "invalid_async_response",
                "The provider accepted a job but returned no usable job receipt; do not resubmit.",
                502,
            )
        return Response(
            json.dumps(
                {
                    "id": job_id,
                    "status": status,
                    "model": settings["candidate"]["model"],
                }
            ),
            status=202,
            content_type="application/json",
        )
    if head.status_code != 200:
        raise rejection(head)
    if operation == "speech":
        if raw.lstrip().startswith(b"{"):
            try:
                decoded = json.loads(raw)
            except (ValueError, UnicodeError):
                decoded = None
            if isinstance(decoded, dict) and "error" in decoded:
                raise GatewayError(
                    "upstream_error", "The speech provider returned an error.", 502
                )
        media_type = (
            head.headers.get("Content-Type", head.headers.get("content-type", ""))
            .split(";", 1)[0]
            .lower()
        )
        if not raw or media_type not in AUDIO_TYPES:
            raise GatewayError(
                "invalid_audio_response",
                "The speech provider did not return binary audio.",
                502,
            )
        return Response(raw, content_type=media_type)
    payload = decode_completion(raw)
    if operation == "transcriptions":
        if not isinstance(payload.get("text"), str):
            raise ValueError("Missing transcription text")
        return Response(
            json.dumps({"text": payload["text"]}), content_type="application/json"
        )
    return _embedding_result(payload, settings, submitted)


def _dispatch(operation, app, auth, proxy):
    reservation = exchange = None
    complete, charged = True, 0
    try:
        reject_idempotency()
        policy = load_policy()
        settings = policy["media"].get(operation)
        if not settings or not eligible(
            settings["candidate"], policy["allow_paid_overage"], app.config
        ):
            raise GatewayError(
                "media_not_configured",
                "No eligible model is configured for this operation.",
                503,
            )
        body, data, content_type = _payload(operation, settings)
        transport = IntelligenceTransport(app.config, auth, proxy)
        token = transport.credential(settings["candidate"])
        if not token:
            raise GatewayError(
                "missing_credentials",
                "No credential is configured for this operation.",
                503,
            )
        reservation = IntelligenceStore.reserve(
            g.authenticated_user["username"], 1, policy, kind=operation
        )
        path = "v1/embeddings" if operation == "embeddings" else f"v1/audio/{operation}"
        exchange = transport.start(
            settings["candidate"],
            body,
            token,
            time.monotonic() + policy["deadline_ms"] / 1000,
            CallerCancellation(request.environ),
            policy["max_response_bytes"],
            path=path,
            data=data,
            content_type=content_type,
        )
        complete, charged = False, 1
        head = exchange.head()
        if _is_fallback_response(head):
            complete, charged = True, 0
            raise rejection(head)
        result = _result(operation, exchange.read(), head, settings, body)
        complete = True
        result.headers["X-Request-ID"] = get_request_id()
        return result
    except GatewayError as error:
        return error_response(error)
    except ValueError:
        return error_response(
            GatewayError(
                "invalid_media_response" if reservation else "invalid_media_request",
                "The media request or response does not satisfy the pinned contract.",
                502 if reservation else 400,
            )
        )
    except Exception:
        return error_response(
            GatewayError(
                "media_gateway_error",
                "The media operation could not be completed; do not replay an uncertain submission.",
                503,
            )
        )
    finally:
        if exchange:
            exchange.close()
        if reservation:
            IntelligenceStore.settle(reservation, charged, complete)


def register_intelligence_media_routes(app, csrf, auth, proxy):
    def register(operation, scope, path):
        def handle():
            return _dispatch(operation, app, auth, proxy)

        handle.__name__ = f"intelligence_{operation}"
        app.route(path, methods=["POST", "OPTIONS"])(
            csrf.exempt(api_authenticate_only(required_scope=scope)(handle))
        )

    register("transcriptions", "audio", "/v1/audio/transcriptions")
    register("speech", "audio", "/v1/audio/speech")
    register("embeddings", "embeddings", "/v1/embeddings")
