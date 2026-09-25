"""Asynchronous video generation across providers behind one OpenAI-style job API.

A job is created on the first working candidate of a route and is then polled on that
provider. The job ID is a signed token naming the provider, model, upstream job and the
caller, so status reads need no local state and survive Container restarts, and no other
key can read or download the job.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass

import requests
from flask import Response

from error_handlers import APIError
from services import cloudflare_ai
from services.media_catalog import TRANSPORT_FAILURE_HEADER

VIDEO_PROVIDERS = frozenset({"openai", "xai", "gemini", "cloudflare"})
CREATE_TIMEOUT = (10, 120)
POLL_TIMEOUT = (10, 60)
DOWNLOAD_TIMEOUT = (10, 300)
MAX_VIDEO_BYTES = 512 * 1024 * 1024
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
_JOB_PREFIX = "video_"
_ASPECT_RATIOS = ("16:9", "9:16", "1:1")
_SIZE = re.compile(r"(\d{3,4})x(\d{3,4})\Z")
_PROCESS_SECRET = secrets.token_bytes(32)


@dataclass(frozen=True)
class VideoRequest:
    prompt: str
    seconds: int = 8
    aspect_ratio: str = "16:9"
    # The highest resolution every provider offers is the default.
    resolution: str = "1080p"
    image_url: str | None = None
    generate_audio: bool = True


def parse_video_request(body: dict) -> VideoRequest:
    prompt = body.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 8000:
        raise APIError("prompt is required and must be at most 8000 characters", status_code=400)
    seconds = body.get("seconds", body.get("duration", 8))
    try:
        seconds = int(str(seconds).rstrip("s"))
    except ValueError:
        raise APIError("seconds must be a whole number", status_code=400) from None
    if not 1 <= seconds <= 20:
        raise APIError("seconds must be from 1 to 20", status_code=400)
    aspect_ratio, resolution = body.get("aspect_ratio", "16:9"), body.get("resolution", "1080p")
    size = _SIZE.fullmatch(str(body.get("size") or ""))
    if size:
        width, height = int(size.group(1)), int(size.group(2))
        aspect_ratio = "1:1" if width == height else "16:9" if width > height else "9:16"
        resolution = "1080p" if min(width, height) >= 1024 else "720p"
    if aspect_ratio not in _ASPECT_RATIOS or resolution not in ("720p", "1080p"):
        raise APIError("aspect_ratio must be 16:9, 9:16 or 1:1 and resolution 720p or 1080p", status_code=400)
    image_url = body.get("image_url")
    if image_url is not None and (not isinstance(image_url, str)
                                  or not re.match(r"(https://|data:image/(png|jpeg|webp);base64,)", image_url)
                                  or len(image_url) > 12_000_000):
        raise APIError("image_url must be an https URL or a PNG, JPEG or WebP data URL", status_code=400)
    return VideoRequest(prompt.strip(), seconds, aspect_ratio, resolution, image_url, body.get("generate_audio", True) is not False)


def _secret() -> bytes:
    configured = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("JWT_SECRET")
    return configured.encode("utf-8") if configured else _PROCESS_SECRET


def issue_job_id(owner: str, provider: str, model: str, upstream: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(
        {"o": owner, "p": provider, "m": model, "u": upstream, "t": int(time.time())},
        separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(_secret(), f"video:{payload}".encode("ascii"), hashlib.sha256).hexdigest()[:40]
    return f"{_JOB_PREFIX}{payload}.{signature}"


def read_job_id(job_id: str, owner: str) -> dict:
    missing = APIError("Video job not found", status_code=404)
    if not isinstance(job_id, str) or not job_id.startswith(_JOB_PREFIX) or len(job_id) > 8192 or "." not in job_id:
        raise missing
    payload, signature = job_id[len(_JOB_PREFIX):].rsplit(".", 1)
    expected = hmac.new(_secret(), f"video:{payload}".encode("ascii"), hashlib.sha256).hexdigest()[:40]
    if not hmac.compare_digest(signature, expected):
        raise missing
    try:
        job = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        raise missing from None
    if job.get("o") != owner or job.get("p") not in VIDEO_PROVIDERS:
        raise missing
    return job


def _nearest(value: int, choices: tuple[int, ...]) -> int:
    return min(choices, key=lambda choice: (abs(choice - value), -choice))


def _openai_size(model: str, request: VideoRequest) -> str:
    portrait = request.aspect_ratio == "9:16"
    if model.startswith("sora-2-pro") and request.resolution == "1080p":
        return "1024x1792" if portrait else "1792x1024"
    return "720x1280" if portrait else "1280x720"


def _json_body(content: bytes) -> dict:
    try:
        body = json.loads(content) if content else None
    except ValueError:
        body = None
    return body if isinstance(body, dict) else {}


def _json(response: requests.Response) -> dict:
    return _json_body(response.content)


def _upstream_id(provider: str, body: dict) -> str | None:
    """The provider's handle for the new job (Cloudflare replies with the finished file)."""
    value = body.get({"openai": "id", "xai": "request_id", "gemini": "name", "cloudflare": "video_url"}[provider])
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    if provider == "gemini" and (not re.fullmatch(r"(?:operations|models)/[A-Za-z0-9_./-]{1,300}", value) or ".." in value):
        return None
    if provider == "cloudflare" and not value.startswith("https://"):
        return None
    if provider in ("openai", "xai") and not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", value):
        return None
    return value


def _failure(status: int, message: str, transport: str | None = None) -> Response:
    response = Response(json.dumps({"error": {"message": message}}), status=status, content_type="application/json")
    if transport:
        response.headers[TRANSPORT_FAILURE_HEADER] = transport
    return response


def _send(method: str, url: str, *, timeout, **kwargs) -> requests.Response | Response:
    """One provider call without retries: a sent job may already be accepted and billed."""
    try:
        return requests.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
    except requests.exceptions.ConnectTimeout:
        return _failure(502, "The video provider could not be reached", "connect")
    except requests.exceptions.ConnectionError as error:
        reason = type(getattr(error.args[0], "reason", None)).__name__ if error.args else ""
        connect = reason in {"NewConnectionError", "NameResolutionError", "ConnectTimeoutError"}
        return _failure(502, "The video provider connection failed", "connect" if connect else "interrupted")
    except requests.exceptions.Timeout:
        return _failure(504, "The video provider did not answer in time", "timeout")


def _gemini_image(image_url: str | None) -> dict | None:
    if not image_url:
        return None
    match = re.match(r"data:(image/(?:png|jpeg|webp));base64,(.+)\Z", image_url, re.DOTALL)
    if not match:
        # Veo takes image bytes; a remote image URL is left to providers that fetch it.
        raise APIError("Veo through Gemini accepts image_url only as a data URL", status_code=400)
    return {"bytesBase64Encoded": match.group(2), "mimeType": match.group(1)}


def create_job(provider: str, model: str, request: VideoRequest, key: str | None, base_url: str, owner: str) -> Response:
    """Start one job; the reply is the public job object or the provider's refusal."""
    body: dict[str, object]
    if provider == "openai":
        body = {"model": model, "prompt": request.prompt, "size": _openai_size(model, request),
                "seconds": str(_nearest(request.seconds, (4, 8, 12)))}
        if request.image_url:
            body["input_reference"] = {"image_url": request.image_url}
        response = _send("POST", f"{base_url.rstrip('/')}/v1/videos", timeout=CREATE_TIMEOUT, json=body,
                         headers={"Authorization": f"Bearer {key}"})
    elif provider == "xai":
        body = {"model": model, "prompt": request.prompt, "duration": min(15, request.seconds),
                "aspect_ratio": request.aspect_ratio, "resolution": request.resolution}
        if request.image_url:
            body["image"] = {"url": request.image_url}
        response = _send("POST", f"{base_url.rstrip('/')}/v1/videos/generations", timeout=CREATE_TIMEOUT, json=body,
                         headers={"Authorization": f"Bearer {key}"})
    elif provider == "gemini":
        instance: dict[str, object] = {"prompt": request.prompt}
        image = _gemini_image(request.image_url)
        if image:
            instance["image"] = image
        aspect_ratio = "16:9" if request.aspect_ratio == "1:1" else request.aspect_ratio
        body = {"instances": [instance], "parameters": {
            "sampleCount": 1, "aspectRatio": aspect_ratio, "resolution": request.resolution,
            "durationSeconds": _nearest(request.seconds, (4, 6, 8))}}
        response = _send("POST", f"{GEMINI_BASE}/models/{model}:predictLongRunning", timeout=CREATE_TIMEOUT,
                         json=body, headers={"x-goog-api-key": key})
    elif provider == "cloudflare":
        if not cloudflare_ai.enabled():
            raise APIError("Cloudflare AI is not bound to this deployment", status_code=503)
        response = cloudflare_ai.post("/v1/videos/generations", {
            "model": model, "prompt": request.prompt, "aspect_ratio": request.aspect_ratio,
            "resolution": request.resolution, "duration": _nearest(request.seconds, (4, 6, 8)),
            "generate_audio": request.generate_audio, **({"image_url": request.image_url} if request.image_url else {})},
            cloudflare_ai.VIDEO_TIMEOUT)
    else:
        raise APIError(f"Video generation is not supported for provider: {provider}", status_code=400)
    if isinstance(response, Response) and (response.status_code >= 400 or TRANSPORT_FAILURE_HEADER in response.headers):
        return response
    body = response.get_data() if isinstance(response, Response) else response.content
    parsed = _json_body(body)
    upstream = _upstream_id(provider, parsed)
    if response.status_code >= 400 or not upstream:
        status = response.status_code if response.status_code >= 400 else 502
        return Response(body or json.dumps({"error": {"message": "The provider did not start a video job"}}),
                        status=status, content_type="application/json")
    job_id = issue_job_id(owner, provider, model, upstream)
    status = "completed" if provider == "cloudflare" else "queued"
    return Response(json.dumps({"id": job_id, "object": "video", "status": status, "model": f"{provider}:{model}",
                                "created_at": int(time.time()), "seconds": request.seconds,
                                "aspect_ratio": request.aspect_ratio, "resolution": request.resolution}),
                    status=200, content_type="application/json")


def job_status(job: dict, job_id: str, key: str | None, base_url: str) -> dict:
    """The job's current state in the public shape."""
    provider, upstream = job["p"], job["u"]
    public = {"id": job_id, "object": "video", "model": f"{provider}:{job['m']}", "created_at": job["t"]}
    if provider == "cloudflare":
        return {**public, "status": "completed", "progress": 100}
    if provider in ("openai", "xai"):
        response = _send("GET", f"{base_url.rstrip('/')}/v1/videos/{upstream}", timeout=POLL_TIMEOUT,
                         headers={"Authorization": f"Bearer {key}"})
    else:
        response = _send("GET", f"{GEMINI_BASE}/{upstream}", timeout=POLL_TIMEOUT, headers={"x-goog-api-key": key})
    if isinstance(response, Response) or response.status_code >= 500:
        # A failed status read is not a failed job: report it and let the caller poll again.
        return {**public, "status": "in_progress", "poll_error": "The provider status could not be read; poll again"}
    body = _json(response)
    if response.status_code >= 400:
        return {**public, "status": "failed", "error": {"message": (body.get("error") or {}).get("message")
                                                         if isinstance(body.get("error"), dict) else "The provider rejected the status request"}}
    if provider == "openai":
        status = {"queued": "queued", "in_progress": "in_progress", "completed": "completed"}.get(body.get("status"), "failed")
        result = {**public, "status": status, "progress": body.get("progress")}
    elif provider == "xai":
        status = {"pending": "in_progress", "done": "completed"}.get(body.get("status"), "failed")
        result = {**public, "status": status}
    else:
        done, error = body.get("done") is True, body.get("error")
        status = "failed" if error else "completed" if done else "in_progress"
        result = {**public, "status": status}
    if result["status"] == "failed":
        error = body.get("error")
        result["error"] = {"message": error.get("message") if isinstance(error, dict) else str(error or body.get("status") or "failed")[:500]}
    return result


def content_source(job: dict, key: str | None, base_url: str) -> tuple[str, dict]:
    """Where the finished file is and the headers needed to read it."""
    provider, upstream = job["p"], job["u"]
    if provider == "cloudflare":
        return upstream, {}
    if provider == "openai":
        return f"{base_url.rstrip('/')}/v1/videos/{upstream}/content", {"Authorization": f"Bearer {key}"}
    if provider == "xai":
        response = _send("GET", f"{base_url.rstrip('/')}/v1/videos/{upstream}", timeout=POLL_TIMEOUT,
                         headers={"Authorization": f"Bearer {key}"})
        url = ((_json(response).get("video") or {}).get("url") if not isinstance(response, Response) else None)
        if not url:
            raise APIError("The video is not ready", status_code=409)
        return url, {}
    response = _send("GET", f"{GEMINI_BASE}/{upstream}", timeout=POLL_TIMEOUT, headers={"x-goog-api-key": key})
    samples = (((_json(response).get("response") or {}).get("generateVideoResponse") or {}).get("generatedSamples")
               if not isinstance(response, Response) else None) or []
    uri = ((samples[0] or {}).get("video") or {}).get("uri") if samples else None
    if not uri:
        raise APIError("The video is not ready", status_code=409)
    return uri, {"x-goog-api-key": key}


def stream_content(url: str, headers: dict) -> Response:
    if not url.startswith("https://"):
        raise APIError("The provider returned an unsupported video location", status_code=502)
    try:
        upstream = requests.get(url, headers=headers, timeout=DOWNLOAD_TIMEOUT, stream=True, allow_redirects=True)
    except requests.exceptions.RequestException:
        raise APIError("The video could not be downloaded; try again", status_code=502) from None
    if upstream.status_code >= 400:
        upstream.close()
        raise APIError("The video is not available", status_code=409 if upstream.status_code in (404, 409) else 502)
    length = int(upstream.headers.get("Content-Length") or 0)
    if length > MAX_VIDEO_BYTES:
        upstream.close()
        raise APIError("The video is too large to relay", status_code=502)

    def generate():
        sent = 0
        try:
            for chunk in upstream.iter_content(1 << 16):
                sent += len(chunk)
                if sent > MAX_VIDEO_BYTES:
                    return
                yield chunk
        finally:
            upstream.close()

    response = Response(generate(), status=200, content_type=upstream.headers.get("Content-Type", "video/mp4"))
    if length:
        response.headers["Content-Length"] = str(length)
    response.headers["Cache-Control"] = "private, no-store"
    return response
