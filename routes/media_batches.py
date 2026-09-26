"""Asynchronous image batches (`/v1/images/batches`) and signed webhooks.

A batch is stored in D1 and run by a Workflow in the Worker (worker/media-jobs.mjs), so
it survives Container sleep. The Workflow sends a few items at a time to
`/internal/media/batch-items`, which the Worker never exposes publicly. Each call carries
a signed principal naming the batch and its owner instead of the owner's API key; the
owner's account is checked again before every call, so deleting the account stops the
batch. Every item runs through the normal image dispatch with its route's failover, and
its images are stored in R2 under IDs derived from the batch and item.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from functools import partial

from flask import g, jsonify, request, url_for

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_auth_required, api_authenticate_only
from routes.media_files import unavailable
from routes.media_images import _error, _image_count, run_image_tasks
from services import media_jobs, media_storage
from services.auto_route_service import AutoRouteService
from services.media_signing import issue_principal, read_principal, webhook_secret
from services.media_urls import public_https_url

DEFAULT_MODEL = "auto:image"
MAX_ITEMS = 500
MAX_IMAGES = 1000
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_PROMPT_CHARS = 32000
MAX_ITEMS_PER_CALL = 8
PRINCIPAL_TTL_SECONDS = 14 * 86400
PRINCIPAL_SCHEME = "MultiLLM-Principal "
BATCH_ID = re.compile(r"imgbatch_[a-f0-9]{32}\Z")
CUSTOM_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
ITEM_FIELDS = frozenset({"model", "prompt", "n", "size", "quality", "background", "output_format", "output_compression",
                         "moderation", "user", "aspect_ratio", "resolution", "style"})
_REFUSALS = {
    "idempotency_conflict": (409, "This Idempotency-Key was already used for a different batch"),
    "too_many_active_batches": (429, "Too many of your batches are queued or running; wait for one to finish"),
    "invalid_request": (400, "The batch was refused as invalid"),
    "not_found": (404, "Batch not found"),
}


def _owner() -> str:
    user = getattr(g, "authenticated_user", None) or {}
    return str(user.get("username") or user.get("id") or "")


def _not_configured():
    if media_jobs.enabled() and media_storage.enabled():
        return None
    return unavailable("batches_not_configured", "Asynchronous batches need the MEDIA_JOBS Workflow, D1 and a "
                       "MEDIA_BUCKET R2 binding on the Worker; see docs/media-storage.md.")


def job_call(operation: str, **fields) -> dict:
    """A media job operation, with the Worker's refusals turned into client errors."""
    try:
        return media_jobs.call(operation, **fields)
    except media_jobs.MediaJobError as error:
        if error.code in _REFUSALS:
            status, message = _REFUSALS[error.code]
            raise APIError(message, status_code=status, payload={"error": error.code}) from None
        raise APIError("Media job storage is unavailable", status_code=503,
                       payload={"error": "batches_not_configured" if error.code == "batches_not_configured"
                                else "batches_unavailable"}) from None


def validated_metadata(value: object) -> dict:
    if value is None:
        return {}
    if (not isinstance(value, dict) or len(value) > 16
            or not all(isinstance(key, str) and 0 < len(key) <= 64 and isinstance(item, str) and len(item) <= 512
                       for key, item in value.items())):
        raise APIError("metadata must be an object of at most 16 string values", status_code=400)
    return value


def public_batch(job: dict) -> dict:
    counts = job.get("counts") or {}
    body = {"id": job["id"], "object": "image.batch", "status": job["status"], "created_at": job["created_at"],
            "started_at": job.get("started_at"), "completed_at": job.get("completed_at"),
            "request_counts": {"total": job["item_count"], **{name: counts.get(name, 0)
                                                               for name in ("queued", "running", "succeeded", "failed", "cancelled")}},
            "metadata": job.get("metadata") or {},
            "results_url": url_for("image_batch_results", batch_id=job["id"], _external=True)}
    if job.get("webhook_url"):
        body["webhook"] = {"url": job["webhook_url"], "status": job.get("webhook_status") or "pending"}
    return body


def _item_images(files: list) -> list:
    images = []
    for file in files if isinstance(files, list) else []:
        if isinstance(file, dict) and isinstance(file.get("id"), str):
            images.append({"url": media_storage.file_url(file["id"]), "file_id": file["id"]})
        elif isinstance(file, dict) and isinstance(file.get("url"), str):
            images.append({"url": file["url"]})
    return images


def principal_user(auth_service_cls, owner: str) -> dict | None:
    """The owner's current account, or None when it was deleted or revoked."""
    record = auth_service_cls._load_user_by_username(owner)
    if record is None or record.get("revoked_at"):
        return None
    return auth_service_cls._public_user(owner, record)


def read_request_principal(kind: str) -> dict:
    header = request.headers.get("Authorization", "")
    if not header.startswith(PRINCIPAL_SCHEME):
        raise APIError("Invalid job principal", status_code=403)
    return read_principal(header[len(PRINCIPAL_SCHEME):].strip(), kind)


def register_media_batch_routes(app, csrf, auth_service_cls, validate_image_model, generate_image) -> None:
    def batch_items(body: dict) -> list[dict]:
        items, defaults = body.get("items"), body.get("defaults", {})
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS or not isinstance(defaults, dict):
            raise APIError(f"items must be a list of 1 to {MAX_ITEMS} objects; defaults must be an object", status_code=400)
        checked_models: set[str] = set()
        prepared, images, seen = [], 0, set()
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise APIError(f"items[{index}] must be an object", status_code=400)
            custom_id = str(item.get("id", index))
            if not CUSTOM_ID.fullmatch(custom_id) or custom_id in seen:
                raise APIError(f"items[{index}].id must be unique and use at most 64 letters, digits or ._:-",
                               status_code=400)
            seen.add(custom_id)
            merged = {"model": DEFAULT_MODEL, **defaults, **{key: value for key, value in item.items() if key != "id"}}
            merged.pop("response_format", None)
            unknown = set(merged) - ITEM_FIELDS
            if unknown:
                raise APIError(f"items[{index}] has an unsupported field: {sorted(unknown)[0]}", status_code=400)
            prompt = merged.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT_CHARS:
                raise APIError(f"items[{index}] needs a prompt of at most {MAX_PROMPT_CHARS} characters", status_code=400)
            images += _image_count(merged)
            model = merged["model"]
            if not isinstance(model, str):
                raise APIError(f"items[{index}].model must be a string", status_code=400)
            if model not in checked_models:
                if AutoRouteService.is_auto_route(model):
                    if AutoRouteService.get_route(model) is None:
                        raise APIError(f"Auto route not found: {model}", status_code=400)
                else:
                    validate_image_model(model)
                checked_models.add(model)
            prepared.append({"custom_id": custom_id, "request": merged})
        if images > MAX_IMAGES:
            raise APIError(f"A batch can produce at most {MAX_IMAGES} images", status_code=400)
        return prepared

    @app.route("/v1/images/batches", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def create_image_batch():
        refused = _not_configured()
        if refused is not None:
            return refused
        if (request.content_length or 0) > MAX_BODY_BYTES:
            raise APIError("A batch request may be at most 2 MiB", status_code=413)
        body = json_object_body()
        if set(body) - {"items", "defaults", "webhook_url", "metadata"}:
            raise APIError("A batch accepts items, defaults, webhook_url and metadata", status_code=400)
        items = batch_items(body)
        webhook_url = public_https_url(body["webhook_url"], "webhook_url") if body.get("webhook_url") is not None else None
        metadata = validated_metadata(body.get("metadata"))
        owner = _owner()
        key = request.headers.get("Idempotency-Key")
        if key is not None and (not key.strip() or len(key) > 256):
            raise APIError("Idempotency-Key must be 1 to 256 characters", status_code=400)
        canonical = json.dumps({"items": items, "webhook_url": webhook_url, "metadata": metadata}, sort_keys=True,
                               separators=(",", ":"))
        suffix = (hashlib.sha256(f"{owner}\0{key}".encode("utf-8")).hexdigest()[:32] if key is not None
                  else secrets.token_hex(16))
        batch_id = f"imgbatch_{suffix}"
        reply = job_call("create_batch", id=batch_id, owner=owner, webhook_url=webhook_url, metadata=metadata,
                         principal=issue_principal("batch", batch_id, owner, PRINCIPAL_TTL_SECONDS),
                         request_digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest(), items=items)
        batch = public_batch(reply["job"])
        if webhook_url:
            batch["webhook"]["secret"] = webhook_secret(owner)
        return jsonify(batch)

    @app.route("/v1/images/batches", methods=["GET"])
    @csrf.exempt
    @api_authenticate_only
    def list_image_batches():
        refused = _not_configured()
        if refused is not None:
            return refused
        limit = request.args.get("limit", default=20, type=int)
        before = request.args.get("before", type=int)
        reply = job_call("list_jobs", owner=_owner(), kind="image_batch", limit=limit, before=before)
        return jsonify({"object": "list", "data": [public_batch(job) for job in reply["jobs"]], "has_more": reply["has_more"]})

    def owned_batch(batch_id: str) -> dict:
        if not BATCH_ID.fullmatch(batch_id):
            raise APIError("Batch not found", status_code=404)
        return job_call("get_job", id=batch_id, owner=_owner(), kind="image_batch")["job"]

    @app.route("/v1/images/batches/<batch_id>", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def get_image_batch(batch_id: str):
        refused = _not_configured()
        return refused if refused is not None else jsonify(public_batch(owned_batch(batch_id)))

    @app.route("/v1/images/batches/<batch_id>/results", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def image_batch_results(batch_id: str):
        refused = _not_configured()
        if refused is not None:
            return refused
        if not BATCH_ID.fullmatch(batch_id):
            raise APIError("Batch not found", status_code=404)
        reply = job_call("list_items", id=batch_id, owner=_owner(), after=request.args.get("after", default=-1, type=int),
                         limit=request.args.get("limit", default=100, type=int))
        data = []
        for item in reply["items"]:
            entry = {"index": item["index"], "id": item["custom_id"], "status": item["status"]}
            if item.get("model"):
                entry["model"] = item["model"]
            if item["status"] == "succeeded":
                entry["images"] = _item_images(item.get("files"))
            if item.get("error"):
                entry["error"] = item["error"]
            data.append(entry)
        return jsonify({"object": "list", "data": data, "has_more": reply["has_more"],
                        "next_after": data[-1]["index"] if data and reply["has_more"] else None})

    @app.route("/v1/images/batches/<batch_id>/cancel", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def cancel_image_batch(batch_id: str):
        refused = _not_configured()
        if refused is not None:
            return refused
        if not BATCH_ID.fullmatch(batch_id):
            raise APIError("Batch not found", status_code=404)
        return jsonify(public_batch(job_call("cancel_job", id=batch_id, owner=_owner())["job"]))

    @app.route("/v1/media/webhook-secret", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def media_webhook_secret():
        """The secret that signs this owner's batch and video webhooks (Standard Webhooks)."""
        return jsonify({"object": "media.webhook_secret", "secret": webhook_secret(_owner()),
                        "headers": ["webhook-id", "webhook-timestamp", "webhook-signature"]})

    @app.route("/internal/media/batch-items", methods=["POST"])
    @csrf.exempt
    def media_batch_items():
        """Run up to eight claimed items for the Workflow; each reports its own outcome."""
        claims = read_request_principal("batch")
        body = request.get_json(silent=True)
        items = body.get("items") if isinstance(body, dict) else None
        if (body.get("job_id") != claims["s"] or not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS_PER_CALL
                or not all(isinstance(item, dict) and type(item.get("index")) is int and isinstance(item.get("request"), dict)
                           for item in items)):
            raise APIError("Invalid batch items", status_code=400)
        try:
            user = principal_user(auth_service_cls, claims["o"])
        except APIError:
            # Nothing was sent to a provider: the Workflow puts the items back in the queue.
            response = jsonify({"retry": True})
            response.status_code = 503
            return response
        if user is None:
            raise APIError("The batch owner's account no longer exists", status_code=403,
                           payload={"error": "principal_rejected"})
        g.authenticated_user = user
        results = run_image_tasks([partial(generate_image, item["request"]) for item in items])
        replies = []
        for item, result in zip(items, results):
            entry = {"index": item["index"]}
            if result["status"] < 400 and result["body"]:
                model = result["headers"].get("X-MultiLLM-Auto-Selected-Model") or item["request"].get("model")
                images = result["body"].get("data") or []
                prefix = f"mb_{claims['s'][len('imgbatch_'):]}_{item['index']}_"
                stored, files = media_storage.store_image_entries(
                    images, owner=claims["o"], want_url=True, model=model,
                    file_ids=[f"{prefix}{number}" for number in range(len(images))])
                # An image that could not be stored keeps its provider URL, which may expire.
                files += [{"url": image["url"]} for image in stored if isinstance(image, dict) and "file_id" not in image
                          and isinstance(image.get("url"), str) and image["url"].startswith("https://")]
                entry.update(status="succeeded" if files else "failed", model=model, files=files)
                if not files:
                    entry["error"] = {"code": "storage_failed", "message": "The images were generated but could not be stored"}
            else:
                error = _error(result)
                entry.update(status="failed", error={"status": error["status"], "message": str(error["message"])[:500]})
            replies.append(entry)
        return jsonify({"version": 1, "results": replies})
