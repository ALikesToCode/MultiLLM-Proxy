"""Durable, single-submission managed request identity and response storage."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import queue
import re
import threading
import time
import uuid
from dataclasses import dataclass
from functools import lru_cache

import requests
from requests.adapters import HTTPAdapter

from services import intelligence_d1_store as private_store
from services.intelligence_contract import GatewayError

MAX_RESPONSE_BYTES = 1_048_576
MAX_DOCUMENT_BYTES = 1_420_000
TTL_SECONDS = 86_400
PRIVATE_URL = "http://intelligence.internal/v1/managed-state/idempotency"
REPLAY_HEADER = "X-MultiLLM-Idempotency"
RESPONSE_HEADERS = frozenset({"content-type", "content-length", "cache-control", "x-multillm-model",
                              "x-multillm-tool-repair"})
_KEY = re.compile(r"[A-Za-z0-9._:/+@-]{1,128}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SLOTS = threading.BoundedSemaphore(8)
logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _warn_invalid_flag():
    logger.warning("Invalid MANAGED_IDEMPOTENCY_ENABLED; managed idempotency disabled")


def idempotency_enabled():
    value = os.environ.get("MANAGED_IDEMPOTENCY_ENABLED", "").strip().lower()
    if value not in {"", "0", "false", "no", "off", "1", "true", "yes", "on"}:
        _warn_invalid_flag()
        return False
    return value in {"1", "true", "yes", "on"}


def unavailable():
    return GatewayError("idempotency_store_unavailable",
                        "The durable idempotency authority is unavailable; do not resubmit with a new key.", 503)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def request_fingerprint(principal, method, path, key, body, revision):
    if not isinstance(key, str) or not _KEY.fullmatch(key):
        raise GatewayError("invalid_idempotency_key", "Idempotency-Key requires 1 to 128 safe ASCII characters.")
    if not isinstance(principal, str) or not principal or len(principal) > 256:
        raise unavailable()
    try:
        scope = hashlib.sha256(_canonical([principal, method, path, key])).hexdigest()
        digest = hashlib.sha256(_canonical([body, revision])).hexdigest()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise GatewayError("invalid_request", "The managed request cannot be normalized.") from None
    return scope, digest


def _submit(document, stopped, deadline, results):
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            if stopped.is_set() or time.monotonic() >= deadline:
                raise unavailable()
            with session.post(PRIVATE_URL, data=document,
                              headers={"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"},
                              timeout=(2, 3), allow_redirects=False, stream=True) as response:
                result = private_store._decode_response(response, stopped, deadline, (200,), MAX_DOCUMENT_BYTES)
        results.put_nowait((True, result))
    except Exception:
        results.put_nowait((False, unavailable()))
    finally:
        _SLOTS.release()


def private_call(body):
    """One fixed private submission, with bounded bytes, concurrency and wall time."""
    if os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip() != "d1":
        raise unavailable()
    try:
        document = _canonical(body)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise unavailable() from None
    if len(document) > MAX_DOCUMENT_BYTES or not _SLOTS.acquire(blocking=False):
        raise unavailable()
    stopped, results = threading.Event(), queue.Queue(maxsize=1)
    deadline = time.monotonic() + 5
    worker = threading.Thread(target=_submit, args=(document, stopped, deadline, results), daemon=True,
                              name="managed-idempotency-store")
    try:
        worker.start()
    except Exception:
        _SLOTS.release()
        raise unavailable() from None
    try:
        success, result = results.get(timeout=max(0, deadline - time.monotonic()))
        if not success:
            raise result
        return result
    except queue.Empty:
        raise unavailable() from None
    finally:
        stopped.set()


def encode_response(response):
    if response.is_streamed or not 200 <= response.status_code < 300:
        return None
    body = response.get_data()
    if len(body) > MAX_RESPONSE_BYTES:
        return None
    headers = [[name, value] for name, value in response.headers if name.lower() in RESPONSE_HEADERS]
    if len(_canonical(headers)) > 16_384:
        return None
    return {"status": response.status_code, "headers": headers, "body": base64.b64encode(body).decode("ascii")}


def decode_response(document):
    from flask import Response
    try:
        if not isinstance(document, dict) or set(document) != {"status", "headers", "body"}:
            raise ValueError()
        if type(document["status"]) is not int or not 200 <= document["status"] < 300:
            raise ValueError()
        headers = document["headers"]
        if not isinstance(headers, list) or len(headers) > 32 or len(_canonical(headers)) > 16_384:
            raise ValueError()
        for pair in headers:
            if not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(value, str) for value in pair):
                raise ValueError()
            if pair[0].lower() not in RESPONSE_HEADERS or any(c in pair[1] for c in "\r\n\x00"):
                raise ValueError()
        encoded = document["body"]
        if not isinstance(encoded, str) or len(encoded) > (MAX_RESPONSE_BYTES + 2) // 3 * 4:
            raise ValueError()
        body = base64.b64decode(encoded, validate=True)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError()
        response = Response(body, status=document["status"], headers=headers)
        response.headers[REPLAY_HEADER] = "replayed"
        return response
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise unavailable() from None


@dataclass(frozen=True)
class Claim:
    scope: str
    digest: str
    owner: str
    status: str
    response: dict | None = None


class IdempotencyStore:
    def __init__(self, call=None):
        self.call = call or private_call

    def _request(self, operation, scope, digest, owner, **values):
        if not _HASH.fullmatch(scope) or not _HASH.fullmatch(digest) or not re.fullmatch(r"[0-9a-f]{32}", owner):
            raise unavailable()
        try:
            document = self.call({"version": 1, "operation": operation, "scope": scope, "digest": digest, "owner": owner, **values})
            if not isinstance(document, dict) or set(document) != {"version", "result"} or type(document["version"]) is not int or document["version"] != 1:
                raise unavailable()
            result = document["result"]
            if not isinstance(result, dict):
                raise unavailable()
            return result
        except Exception:
            raise unavailable() from None

    def claim(self, scope, digest, *, pending_seconds=3600):
        owner = uuid.uuid4().hex
        result = self._request("claim", scope, digest, owner, pending_seconds=pending_seconds)
        status = result.get("status")
        if status not in {"claimed", "pending", "conflict", "completed", "unknown"}:
            raise unavailable()
        expected = {"status", "response"} if status == "completed" else {"status"}
        if set(result) != expected:
            raise unavailable()
        return Claim(scope, digest, owner, status, result.get("response"))

    def transition(self, claim, operation, **values):
        result = self._request(operation, claim.scope, claim.digest, claim.owner, **values)
        if set(result) != {"changed"} or type(result["changed"]) is not bool:
            raise unavailable()
        return result["changed"]
