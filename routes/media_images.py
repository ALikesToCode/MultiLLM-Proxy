"""Automatic image routes: per-candidate settings, failover, fan-out and batches.

An image route tries its candidates in order. A candidate that returns any HTTP error
has delivered no image, so the next one is tried; only a transport failure after the
request was sent (a timeout or dropped connection) stops the route, because that
generation may already have been billed.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from flask import Response, copy_current_request_context, jsonify

from error_handlers import APIError
from routes.auto_routes import AutoRouteCandidateUnavailable, dispatch_auto_route
from services.media_catalog import (
    DEFAULT_IMAGE_QUALITY,
    TRANSPORT_FAILURE_HEADER,
    prepare_image_payload,
)
from services.model_registry import ModelRegistry

logger = logging.getLogger(__name__)

IMAGE_PARALLELISM = 4
MAX_IMAGES_PER_REQUEST = 10
MAX_BATCH_ITEMS = 16
MAX_BATCH_IMAGES = 32
# Base64 images are large; without URLs a batch returns at most this many images.
MAX_BATCH_INLINE_IMAGES = 8
# Refusals raised before any request reached the provider.
_PRE_GENERATION_STATUSES = frozenset({400, 401, 402, 403, 404, 409, 422, 429, 503})
_FORWARDED_HEADERS = ("X-MultiLLM-Auto-Route", "X-MultiLLM-Auto-Selected-Model", "X-MultiLLM-Auto-Attempts")


def image_fail_over(response: Response) -> bool:
    """Whether the next image candidate may run without risking a second charge."""
    kind = response.headers.get(TRANSPORT_FAILURE_HEADER)
    if kind:
        return kind == "connect"
    return response.status_code >= 400


def _image_count(payload: dict) -> int:
    count = payload.get("n", 1)
    if type(count) is not int or not 1 <= count <= MAX_IMAGES_PER_REQUEST:
        raise APIError(f"n must be an integer from 1 to {MAX_IMAGES_PER_REQUEST}", status_code=400)
    return count


def _dispatch_single(payload: dict, validate_candidate: Callable[[str], None],
                     dispatch_candidate: Callable[[dict], Response],
                     prepare: Callable[[str, str, dict], dict] = prepare_image_payload) -> Response:
    def dispatch_prepared(candidate_payload: dict, candidate: str, route_decision: str) -> Response:
        provider, provider_model = ModelRegistry.parse_model_id(candidate)
        prepared = prepare(provider, provider_model, candidate_payload)
        prepared["model"] = candidate
        try:
            return dispatch_candidate(prepared)
        except APIError as error:
            if error.status_code in _PRE_GENERATION_STATUSES:
                raise AutoRouteCandidateUnavailable(error.message) from error
            raise

    return dispatch_auto_route(payload, validate_candidate=validate_candidate,
                               dispatch_candidate=dispatch_prepared, fail_over=image_fail_over)


def _read(response: Response) -> dict:
    """Status, JSON body and route headers of a finished image response."""
    try:
        body = response.get_data()
    finally:
        response.close()
    try:
        parsed = json.loads(body) if body else None
    except ValueError:
        parsed = None
    return {"status": response.status_code, "body": parsed if isinstance(parsed, dict) else None,
            "headers": {name: response.headers[name] for name in _FORWARDED_HEADERS if name in response.headers}}


def run_image_tasks(tasks: list[Callable[[], Response]]) -> list[dict]:
    """Run image requests in parallel, each in a copy of the caller's request context."""
    def finish(task):
        try:
            return _read(task())
        except APIError as error:
            return {"status": error.status_code, "body": {"error": {"message": error.message}}, "headers": {}}
        except Exception as error:  # One failed image must not discard the others.
            logger.warning("Image task failed (%s)", type(error).__name__)
            return {"status": 502, "body": {"error": {"message": "The image request failed"}}, "headers": {}}

    with ThreadPoolExecutor(max_workers=min(IMAGE_PARALLELISM, len(tasks))) as pool:
        futures = [pool.submit(copy_current_request_context(lambda task=task: finish(task))) for task in tasks]
        return [future.result() for future in futures]


def _error(result: dict) -> dict:
    error = (result.get("body") or {}).get("error")
    message = error.get("message") if isinstance(error, dict) else error if isinstance(error, str) else None
    return {"status": result["status"], "message": message or f"The image request failed with HTTP {result['status']}"}


def dispatch_auto_image_generation(payload: dict, *, validate_candidate: Callable[[str], None],
                                   dispatch_candidate: Callable[[dict], Response],
                                   prepare: Callable[[str, str, dict], dict] = prepare_image_payload) -> Response:
    """One image request through an automatic route, fanning n images out in parallel.

    Edits pass their own `prepare`, which keeps only the fields an edit accepts.
    """
    payload = dict(payload)
    payload.setdefault("quality", DEFAULT_IMAGE_QUALITY)
    count = _image_count(payload)
    if count == 1:
        return _dispatch_single(payload, validate_candidate, dispatch_candidate, prepare)
    # Many image models generate one image per request, so each image is its own
    # request and may fall back independently.
    single = {**payload, "n": 1}
    results = run_image_tasks([lambda: _dispatch_single(single, validate_candidate, dispatch_candidate, prepare)] * count)
    succeeded = [result for result in results if result["status"] < 400 and result["body"]]
    if not succeeded:
        failure = results[-1]
        return Response(json.dumps(failure["body"] or {"error": _error(failure)}), status=failure["status"],
                        content_type="application/json")
    response = jsonify({"created": int(time.time()),
                        "data": [image for result in succeeded for image in result["body"].get("data") or []]})
    response.headers["X-MultiLLM-Images-Requested"] = str(count)
    response.headers["X-MultiLLM-Images-Returned"] = str(len(response.get_json()["data"]))
    response.headers["X-MultiLLM-Auto-Selected-Models"] = ",".join(
        dict.fromkeys(result["headers"].get("X-MultiLLM-Auto-Selected-Model", "") for result in succeeded if result["headers"]))
    return response


def run_image_batch(body: dict, dispatch: Callable[[dict], Response]) -> dict:
    """Different prompts, sizes and models in one call; each item reports its own outcome."""
    items, defaults = body.get("items"), body.get("defaults", {})
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_BATCH_ITEMS or not isinstance(defaults, dict):
        raise APIError(f"items must be a list of 1 to {MAX_BATCH_ITEMS} objects; defaults must be an object", status_code=400)
    if set(body) - {"items", "defaults"}:
        raise APIError("A batch accepts only items and defaults", status_code=400)
    requests_by_item, total = [], 0
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise APIError(f"items[{index}] must be an object", status_code=400)
        request_body = {"model": "auto:image", **defaults, **{key: value for key, value in item.items() if key != "id"}}
        if not isinstance(request_body.get("prompt"), str) or not request_body["prompt"].strip():
            raise APIError(f"items[{index}] needs a prompt", status_code=400)
        total += _image_count(request_body)
        requests_by_item.append(request_body)
    inline = any(request_body.get("response_format", "b64_json") != "url" for request_body in requests_by_item)
    limit = MAX_BATCH_INLINE_IMAGES if inline else MAX_BATCH_IMAGES
    if total > limit:
        raise APIError(f"A batch can return at most {limit} images"
                       + ("; request response_format url for up to 32" if inline else ""), status_code=400)
    results = run_image_tasks([partial(dispatch, request_body) for request_body in requests_by_item])
    data = []
    for index, (item, result) in enumerate(zip(items, results)):
        entry = {"index": index, "id": item.get("id", str(index))}
        if result["status"] < 400 and result["body"]:
            entry.update(status="succeeded", images=result["body"].get("data") or [],
                         model=result["headers"].get("X-MultiLLM-Auto-Selected-Model") or requests_by_item[index]["model"])
        else:
            entry.update(status="failed", error=_error(result))
        data.append(entry)
    succeeded = [entry for entry in data if entry["status"] == "succeeded"]
    return {"object": "image.batch", "data": data,
            "summary": {"items": len(data), "succeeded": len(succeeded), "failed": len(data) - len(succeeded),
                        "images": sum(len(entry["images"]) for entry in succeeded)}}
