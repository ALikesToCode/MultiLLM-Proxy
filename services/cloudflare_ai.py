"""Cloudflare AI through the Worker's private outbound handler (`http://ai.internal`).

The Worker's AI binding runs Workers AI models and, through AI Gateway, third-party
models such as OpenAI GPT Image and Google Veo with Cloudflare billing and zero data
retention. No provider credential reaches the Container.
"""

import json
import os

import requests
from flask import Response

from services.media_catalog import TRANSPORT_FAILURE_HEADER

ORIGIN = "http://ai.internal"
IMAGE_TIMEOUT = (5, 600)
# The binding returns a finished clip; Veo generation takes minutes.
VIDEO_TIMEOUT = (5, 900)
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


def enabled() -> bool:
    return os.environ.get("CLOUDFLARE_AI_ENABLED", "").strip().lower() == "true"


def is_cloudflare_model(model_id) -> bool:
    return isinstance(model_id, str) and model_id.lower().startswith("cloudflare:")


def _transport_failure(kind: str) -> Response:
    response = Response(json.dumps({"error": {"message": "Cloudflare AI could not be reached", "type": "upstream_transport_error"}}),
                        status=502 if kind == "connect" else 504, content_type="application/json")
    response.headers[TRANSPORT_FAILURE_HEADER] = kind
    return response


def post(path: str, payload: dict, timeout) -> requests.Response | Response:
    """One private call, never retried: a sent generation may already be billed."""
    with requests.Session() as session:
        session.trust_env = False
        try:
            response = session.post(ORIGIN + path, json=payload, timeout=timeout, allow_redirects=False, stream=True)
        except requests.exceptions.ConnectionError as error:
            connect = isinstance(error, requests.exceptions.ConnectTimeout) or "NewConnectionError" in repr(error)
            return _transport_failure("connect" if connect else "interrupted")
        except requests.exceptions.Timeout:
            return _transport_failure("timeout")
        with response:
            length = int(response.headers.get("Content-Length") or 0)
            if length > MAX_RESPONSE_BYTES:
                return _transport_failure("interrupted")
            body = bytearray()
            for chunk in response.iter_content(65536):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    return _transport_failure("interrupted")
            return Response(bytes(body), status=response.status_code,
                            content_type=response.headers.get("Content-Type") or "application/json")


def _not_bound() -> Response:
    return Response(json.dumps({"error": {"message": "Cloudflare AI is not bound to this deployment"}}),
                    status=503, content_type="application/json")


def generate_image(payload: dict) -> Response:
    if not enabled():
        return _not_bound()
    body = {**payload, "model": payload["model"].split(":", 1)[1]}
    return post("/v1/images/generations", body, IMAGE_TIMEOUT)


def run_audio(path: str, body: dict, timeout) -> Response:
    """Workers AI embeddings, Aura speech or Whisper transcription (`body["model"]` has no prefix)."""
    return post(path, body, timeout) if enabled() else _not_bound()


def edit_image(payload: dict, images: list[str]) -> Response:
    """Edit through AI Gateway: `images` are data URLs, sent to OpenAI's edit endpoint."""
    if not enabled():
        return _not_bound()
    body = {**payload, "model": payload["model"].split(":", 1)[1], "images": images}
    return post("/v1/images/edits", body, IMAGE_TIMEOUT)
