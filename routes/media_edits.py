"""Image edits and reference-image generation under the image routes' failover rule.

`POST /v1/images/edits` takes OpenAI's multipart form (`image` or `image[]`, up to 16
files, and an optional PNG `mask`) or, as a convenience, JSON whose `images` and `mask`
are HTTPS or data URLs. A generation request that carries `images` runs the same way,
with the images as references. Each candidate receives its closest settings
(services.media_catalog) in the format it accepts: OpenAI's edit form, xAI's JSON image
URLs or the `images` array of Cloudflare's AI binding. Candidates that cannot take the
request (no edit support, a mask they ignore, too many images) are skipped before any
request is sent.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass

import requests
from flask import Response, has_request_context, request

from error_handlers import APIError
from route_helpers import stream_upstream_response
from routes.media_images import _image_count, dispatch_auto_image_generation
from routes.provider_credentials import _add_credential_attempt_headers, _request_with_provider_token_rotation
from routes.unified_transport import send_unified_image_request
from services import cloudflare_ai, media_storage
from services.auto_route_service import AutoRouteService
from services.media_catalog import TRANSPORT_FAILURE_HEADER, image_edit_support, prepare_image_edit_payload
from services.model_registry import ModelRegistry

DEFAULT_EDIT_ROUTE = "auto:image-edit"
DEFAULT_REFERENCE_ROUTE = "auto:image"
MAX_EDIT_IMAGES = 16
MAX_IMAGE_BYTES = 20 * 1024 * 1024
MAX_MASK_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 30 * 1024 * 1024
# Cloudflare receives base64 images inside one JSON body to the Worker.
MAX_CLOUDFLARE_BYTES = 16 * 1024 * 1024
MAX_PROMPT_CHARS = 32000
_EXTENSIONS = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}
_INTEGER_FIELDS = frozenset({"n", "output_compression"})
_DATA_URL = re.compile(r"data:image/(?:png|jpeg|jpg|webp);base64,([A-Za-z0-9+/=\s]+)\Z")


@dataclass(frozen=True)
class SourceImage:
    data: bytes
    content_type: str

    def data_url(self) -> str:
        return f"data:{self.content_type};base64,{base64.b64encode(self.data).decode('ascii')}"

    def filename(self, index: int) -> str:
        return f"image-{index}.{_EXTENSIONS[self.content_type]}"


@dataclass(frozen=True)
class EditInputs:
    images: tuple[SourceImage, ...]
    mask: SourceImage | None = None

    @property
    def total_bytes(self) -> int:
        return sum(len(image.data) for image in self.images) + (len(self.mask.data) if self.mask else 0)


def _sniff(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _source(data: bytes, field: str, limit: int, *, png_only: bool = False) -> SourceImage:
    if not data:
        raise APIError(f"{field} is empty", status_code=400)
    if len(data) > limit:
        raise APIError(f"{field} is larger than {limit // (1024 * 1024)} MiB", status_code=413)
    content_type = _sniff(data)
    if content_type is None or (png_only and content_type != "image/png"):
        raise APIError(f"{field} must be a {'PNG' if png_only else 'PNG, JPEG or WebP'} image", status_code=400)
    return SourceImage(data, content_type)


def _inputs(images: list[SourceImage], mask: SourceImage | None) -> EditInputs:
    if not images:
        raise APIError("At least one image is required", status_code=400)
    inputs = EditInputs(tuple(images), mask)
    if inputs.total_bytes > MAX_TOTAL_BYTES:
        raise APIError(f"The images may total at most {MAX_TOTAL_BYTES // (1024 * 1024)} MiB", status_code=413)
    return inputs


def _check_count(count: int) -> None:
    if count > MAX_EDIT_IMAGES:
        raise APIError(f"An edit accepts at most {MAX_EDIT_IMAGES} images", status_code=400)


def parse_multipart_edit() -> tuple[dict, EditInputs]:
    """OpenAI's edit form: `image` or `image[]` files, an optional `mask` and text fields."""
    if set(request.files) - {"image", "image[]", "mask"}:
        raise APIError("Upload images as image or image[] and the mask as mask", status_code=400)
    uploads = request.files.getlist("image") + request.files.getlist("image[]")
    _check_count(len(uploads))
    masks = request.files.getlist("mask")
    if len(masks) > 1:
        raise APIError("Send at most one mask", status_code=400)
    images = [_source(upload.read(MAX_IMAGE_BYTES + 1), "image", MAX_IMAGE_BYTES) for upload in uploads]
    mask = _source(masks[0].read(MAX_MASK_BYTES + 1), "mask", MAX_MASK_BYTES, png_only=True) if masks else None
    payload: dict[str, object] = {}
    for name, value in request.form.items():
        if name in _INTEGER_FIELDS:
            try:
                payload[name] = int(value)
            except ValueError:
                raise APIError(f"{name} must be an integer", status_code=400) from None
        else:
            payload[name] = value
    return payload, _inputs(images, mask)


def reference_values(body: dict) -> list | None:
    value = body.get("images", body.get("image"))
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


def _reference(value: object, field: str, limit: int, *, png_only: bool = False) -> SourceImage:
    if isinstance(value, dict):
        value = value.get("image_url", value.get("url"))
        if isinstance(value, dict):
            value = value.get("url")
    if not isinstance(value, str):
        raise APIError(f"{field} must be an https URL or an image data URL", status_code=400)
    match = _DATA_URL.match(value)
    if match:
        try:
            data = base64.b64decode(re.sub(r"\s", "", match.group(1)), validate=True)
        except (binascii.Error, ValueError):
            raise APIError(f"{field} is not valid base64", status_code=400) from None
    elif value.startswith("data:"):
        raise APIError(f"{field} must be a PNG, JPEG or WebP data URL", status_code=400)
    else:
        data, _ = media_storage.fetch_public(value, max_bytes=limit, field=field)
    return _source(data, field, limit, png_only=png_only)


def parse_json_edit(body: dict) -> tuple[dict, EditInputs]:
    """JSON edits: `images` (or `image`) and `mask` as HTTPS or data URLs."""
    references = reference_values(body)
    if not references:
        raise APIError("images must list at least one https or data URL", status_code=400)
    _check_count(len(references))
    images, total = [], 0
    for index, value in enumerate(references):
        image = _reference(value, f"images[{index}]", min(MAX_IMAGE_BYTES, MAX_TOTAL_BYTES - total))
        total += len(image.data)
        images.append(image)
    mask = None
    if body.get("mask") is not None:
        mask = _reference(body["mask"], "mask", MAX_MASK_BYTES, png_only=True)
    payload = {name: value for name, value in body.items() if name not in ("images", "image", "mask")}
    return payload, _inputs(images, mask)


def has_reference_images(payload: dict) -> bool:
    return payload.get("images") is not None or payload.get("image") is not None


def validate_edit_candidate(app, auth_service_cls, proxy_service_cls, candidate: str, inputs: EditInputs) -> None:
    """Refuse, before any request, a candidate that cannot perform this edit."""
    from routes.unified import _validate_image_candidate

    provider, provider_model = ModelRegistry.parse_model_id(candidate)
    support = image_edit_support(provider, provider_model)
    if support is None:
        raise APIError(f"Image edits are not supported for model: {candidate}", status_code=400)
    if inputs.mask is not None and not support.mask:
        raise APIError(f"{candidate} does not accept a mask", status_code=400)
    if len(inputs.images) > support.max_images:
        raise APIError(f"{candidate} accepts at most {support.max_images} source images", status_code=400)
    if support.transport == "cloudflare" and inputs.total_bytes > MAX_CLOUDFLARE_BYTES:
        raise APIError(f"{candidate} accepts at most {MAX_CLOUDFLARE_BYTES // (1024 * 1024)} MiB of images",
                       status_code=413)
    _validate_image_candidate(app, auth_service_cls, proxy_service_cls, candidate)


def _edit_body(provider_model: str, payload: dict, inputs: EditInputs, transport: str) -> tuple[bytes, str]:
    if transport == "xai":
        sources = [{"url": image.data_url(), "type": "image_url"} for image in inputs.images]
        body = {**payload, "model": provider_model, **({"image": sources[0]} if len(sources) == 1 else {"images": sources})}
        return json.dumps(body, separators=(",", ":")).encode("utf-8"), "application/json"
    fields = {name: str(value) for name, value in payload.items() if name != "model" and value is not None}
    fields["model"] = provider_model
    # OpenAI's SDKs name a single file `image` and a list `image[]`.
    name = "image" if len(inputs.images) == 1 else "image[]"
    files = [(name, (image.filename(index), image.data, image.content_type)) for index, image in enumerate(inputs.images)]
    if inputs.mask is not None:
        files.append(("mask", ("mask.png", inputs.mask.data, "image/png")))
    prepared = requests.Request("POST", "https://placeholder.invalid", data=fields, files=files).prepare()
    return prepared.body, prepared.headers["Content-Type"]


def dispatch_edit_candidate(app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload: dict,
                            inputs: EditInputs) -> Response:
    """Send one prepared edit to one provider:model."""
    provider, provider_model = ModelRegistry.parse_model_id(payload["model"])
    support = image_edit_support(provider, provider_model)
    if support is None:
        raise APIError(f"Image edits are not supported for model: {payload['model']}", status_code=400)
    started, status = time.time(), 502
    try:
        if support.transport == "cloudflare":
            response = cloudflare_ai.edit_image(payload, [image.data_url() for image in inputs.images])
            status = response.status_code
            return response
        raw_body, content_type = _edit_body(provider_model, payload, inputs, support.transport)
        headers = {"Content-Type": content_type}
        if has_request_context() and request.headers.get("Idempotency-Key"):
            headers["Idempotency-Key"] = request.headers["Idempotency-Key"]
        origin = (app.config["NANOGPT_STANDARD_BASE_URL"] if provider == "nanogpt"
                  else app.config["API_BASE_URLS"][provider])

        def send(token: str):
            return send_unified_image_request(
                proxy_service_cls, provider=provider, token=token, request_headers=headers, request_args={},
                upstream_path="v1/images/edits", raw_body=raw_body, primary_origin=origin,
                secondary_origin=app.config["AIHUBMIX_BACKUP_BASE_URL"] if provider == "aihubmix" else None)

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


def dispatch_image_edit(app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload: dict,
                        inputs: EditInputs, *, default_route: str = DEFAULT_EDIT_ROUTE) -> Response:
    """An edit on an automatic route (with failover) or on one provider:model."""
    payload = dict(payload)
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT_CHARS:
        raise APIError(f"prompt is required and must be at most {MAX_PROMPT_CHARS} characters", status_code=400)
    if payload.get("stream") not in (None, False, "false"):
        raise APIError("Streaming image edits are not supported", status_code=400)
    payload.pop("stream", None)
    payload["model"] = payload.get("model") or default_route
    model = payload["model"]
    if not isinstance(model, str):
        raise APIError("model must be a string", status_code=400)
    _image_count(payload)

    def validate(candidate: str) -> None:
        validate_edit_candidate(app, auth_service_cls, proxy_service_cls, candidate, inputs)

    def dispatch(prepared: dict) -> Response:
        return dispatch_edit_candidate(app, auth_service_cls, metrics_service_cls, proxy_service_cls, prepared, inputs)

    if AutoRouteService.is_auto_route(model):
        return dispatch_auto_image_generation(payload, validate_candidate=validate, dispatch_candidate=dispatch,
                                              prepare=prepare_image_edit_payload)
    try:
        provider, provider_model = ModelRegistry.parse_model_id(model)
    except ValueError as error:
        raise APIError(str(error), status_code=400) from error
    validate(model)
    prepared = prepare_image_edit_payload(provider, provider_model, payload)
    prepared["model"] = model
    return dispatch(prepared)


def dispatch_reference_generation(app, auth_service_cls, metrics_service_cls, proxy_service_cls,
                                  body: dict) -> Response:
    """A generation request with reference images runs on candidates that accept them."""
    payload, inputs = parse_json_edit(body)
    return dispatch_image_edit(app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload, inputs,
                               default_route=DEFAULT_REFERENCE_ROUTE)
