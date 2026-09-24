"""Bounded access to the Knowledge Worker's private Container outbound binding."""

import json
import os
import queue
import re
import threading
import time

import requests
from requests.adapters import HTTPAdapter

from services.knowledge_native import NATIVE_OPERATIONS

ENDPOINT = "http://knowledge.internal/v1/dispatch"
MAX_REQUEST_BYTES = 65536
# Provider and Alexandria transports accept at most 1 MiB of upstream JSON. The Worker
# re-encodes it inside {version, result} with receipt fields: strings never grow, but a
# number such as 1e20 becomes 21 digits (at most 5.25x). Rejecting that envelope here
# would lose a result that has already been charged.
UPSTREAM_JSON_BYTES = 1048576
MAX_RESPONSE_BYTES = 6 * UPSTREAM_JSON_BYTES
# Provider tools may wait up to 45 s upstream (for example a DeepWiki answer).
DEADLINE_SECONDS = 55
_SLOTS = threading.BoundedSemaphore(8)
_OPERATIONS = frozenset({
    "context", "search", "artifact", "status", "sources.create", "sources.update",
    "sources.refresh", "jobs.cancel", "policy.update",
    "alexandria.search", "alexandria.inspect", "alexandria.execute", "alexandria.receipt",
    *NATIVE_OPERATIONS,
})
_CODE = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")


class KnowledgeError(Exception):
    """A safe domain or transport failure that may be returned to clients."""

    def __init__(self, code, message, status=503):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def enabled():
    return os.environ.get("KNOWLEDGE_SERVICE_ENABLED", "").strip().lower() == "true"


def setup_status():
    return {
        "enabled": False, "ready": False,
        "setup": [{"id": "service", "label": "Knowledge service binding",
                   "configured": False,
                   "detail": "Deploy and connect the private Knowledge Worker to enable this page."}],
        "providers": [], "policy": None, "generation": None, "sources": [],
        "jobs": [], "usage": [],
    }


def principal_for(user):
    """Project only persisted identity and Knowledge permissions into the binding."""
    identity = user.get("id") or user.get("username")
    scopes = user.get("scopes") or []
    if not isinstance(identity, str) or not identity or len(identity) > 128:
        raise KnowledgeError("invalid_principal", "The authenticated identity is unavailable.", 403)
    if user.get("is_admin") or "admin" in scopes:
        scopes = ["knowledge:read", "knowledge:manage"]
    return {"id": identity, "scopes": [scope for scope in scopes
            if scope in {"knowledge:read", "knowledge:manage"}]}


def _unavailable():
    return KnowledgeError("knowledge_unavailable",
                          "The Knowledge service is unavailable. No automatic retry was started.")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("Invalid JSON constant")


def _decode(response, stopped, deadline):
    if response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise _unavailable()
    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
        raise _unavailable()
    length = response.headers.get("Content-Length")
    if length is not None and (not length.isascii() or not length.isdecimal()
                               or int(length) > MAX_RESPONSE_BYTES):
        raise _unavailable()
    body = bytearray()
    for chunk in response.iter_content(8192):
        if stopped.is_set() or time.monotonic() >= deadline:
            raise _unavailable()
        body.extend(chunk)
        if len(body) > MAX_RESPONSE_BYTES:
            raise _unavailable()
    try:
        payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                             parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError):
        raise _unavailable() from None
    if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] != 1:
        raise _unavailable()
    if 200 <= response.status_code < 300 and set(payload) == {"version", "result"}:
        if not isinstance(payload["result"], (dict, list)):
            raise _unavailable()
        return payload["result"]
    error = payload.get("error")
    if (not 400 <= response.status_code < 600 or set(payload) != {"version", "error"}
            or not isinstance(error, dict) or set(error) != {"code", "message"}
            or not isinstance(error["code"], str) or not _CODE.fullmatch(error["code"])
            or not isinstance(error["message"], str) or not 0 < len(error["message"]) <= 1000):
        raise _unavailable()
    raise KnowledgeError(error["code"], error["message"], response.status_code)


def _submit(body, stopped, deadline, results):
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            if stopped.is_set():
                return
            with session.post(ENDPOINT, data=body,
                              headers={"Content-Type": "application/json", "Accept": "application/json",
                                       "Accept-Encoding": "identity"},
                              timeout=(3, DEADLINE_SECONDS), allow_redirects=False, stream=True) as response:
                result = _decode(response, stopped, deadline)
        results.put((result, None))
    except KnowledgeError as error:
        results.put((None, error))
    except Exception:
        results.put((None, _unavailable()))
    finally:
        _SLOTS.release()


def dispatch(operation, user, payload=None):
    if operation not in _OPERATIONS:
        raise ValueError("Unsupported Knowledge operation")
    if not enabled():
        if operation == "status":
            return setup_status()
        raise KnowledgeError("setup_needed", "The private Knowledge service has not been connected.")
    envelope = {"version": 1, "operation": operation,
                "principal": principal_for(user), "payload": payload or {}}
    body = json.dumps(envelope, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise KnowledgeError("request_too_large", "The Knowledge request exceeds 64 KiB.", 413)
    if not _SLOTS.acquire(blocking=False):
        raise KnowledgeError("knowledge_busy", "Knowledge requests are at capacity. Try again later.", 503)
    stopped = threading.Event()
    results = queue.Queue(maxsize=1)
    deadline = time.monotonic() + DEADLINE_SECONDS
    thread = threading.Thread(target=_submit, args=(body, stopped, deadline, results),
                              daemon=True, name="knowledge-request")
    try:
        thread.start()
    except Exception:
        _SLOTS.release()
        raise _unavailable() from None
    try:
        result, error = results.get(timeout=DEADLINE_SECONDS)
        if error is not None:
            raise error
        return result
    except queue.Empty:
        raise KnowledgeError("knowledge_timeout",
                             "The Knowledge request timed out. Accepted work may still finish; no retry was started.", 504) from None
    finally:
        stopped.set()
