"""Principal-owned Responses history and completion-only persistence."""
from __future__ import annotations

import copy
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
from functools import lru_cache, wraps

import requests
from flask import current_app, g, has_request_context, request
from requests.adapters import HTTPAdapter

from services import intelligence_d1_store as private_store
from services.generation_deadline import current_deadline
from services.intelligence_contract import GatewayError
from services.retention_policy import request_policy

ID_PREFIX = "gwresp_"
MAX_STATE_BYTES = 1_048_576
MAX_DOCUMENT_BYTES = MAX_STATE_BYTES + 16_384
TTL_SECONDS = 86_400
MAX_DEPTH = 16
PRIVATE_URL = "http://intelligence.internal/v1/managed-state/responses"
_ID = re.compile(r"gwresp_[0-9a-f]{32}\Z")
_SLOTS = threading.BoundedSemaphore(8)
logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _warn_invalid_flag():
    logger.warning("Invalid HOSTED_RESPONSES_ENABLED; hosted Responses disabled")


def enabled():
    flag = os.environ.get("HOSTED_RESPONSES_ENABLED", "").strip().lower()
    if flag not in {"", "0", "false", "off", "no", "1", "true", "on", "yes"}:
        _warn_invalid_flag()
        return False
    return flag in {"1", "true", "on", "yes"}


def now():
    return int(time.time())


def gateway_id(value):
    return isinstance(value, str) and value.startswith(ID_PREFIX)


def unavailable():
    return GatewayError("responses_store_unavailable",
                        "Hosted Responses storage is unavailable; a generation will not be resubmitted.", 503)


def not_found():
    return GatewayError("response_not_found", "The stored response was not found.", 404)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def principal_owner():
    user = getattr(g, "authenticated_user", None) or {}
    principal = user.get("id") or user.get("username")
    if not isinstance(principal, (str, int)) or not str(principal):
        raise unavailable()
    return hashlib.sha256(canonical([user.get("tenant_id"), str(principal)])).hexdigest()


def _submit(document, stopped, deadline, results):
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            if stopped.is_set() or time.monotonic() >= deadline:
                raise unavailable()
            with session.post(PRIVATE_URL, data=document, headers={"Content-Type": "application/json",
                              "Accept": "application/json", "Accept-Encoding": "identity"},
                              timeout=(2, 3), allow_redirects=False, stream=True) as response:
                result = private_store._decode_response(response, stopped, deadline, (200,), MAX_DOCUMENT_BYTES)
        results.put_nowait((True, result))
    except Exception:
        results.put_nowait((False, unavailable()))
    finally:
        _SLOTS.release()


def private_call(body):
    """A fixed private hop, bounded in bytes, concurrency and wall time, with no retries."""
    if os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip() != "d1":
        raise unavailable()
    try:
        document = canonical(body)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise unavailable() from None
    if len(document) > MAX_DOCUMENT_BYTES or not _SLOTS.acquire(blocking=False):
        raise unavailable()
    stopped, results = threading.Event(), queue.Queue(maxsize=1)
    deadline = time.monotonic() + 5
    worker = threading.Thread(target=_submit, args=(document, stopped, deadline, results),
                              daemon=True, name="responses-state-store")
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


class ResponsesStateStore:
    def __init__(self, call=None):
        self.call = call or private_call

    def operation(self, operation, **values):
        try:
            document = self.call({"version": 1, "operation": operation, **values})
            if (not isinstance(document, dict) or set(document) != {"version", "result"}
                    or type(document["version"]) is not int or document["version"] != 1
                    or not isinstance(document["result"], dict)):
                raise unavailable()
            return document["result"]
        except Exception:
            raise unavailable() from None

    def probe(self):
        if self.operation("probe") != {"ready": True}:
            raise unavailable()

    def get(self, owner, response_id):
        if not isinstance(response_id, str) or not _ID.fullmatch(response_id):
            raise not_found()
        result = self.operation("get", owner=owner, id=response_id)
        if set(result) != {"state"}:
            raise unavailable()
        row = result["state"]
        if row is None:
            raise not_found()
        if (not isinstance(row, dict) or row.get("id") != response_id or row.get("owner") != owner
                or type(row.get("depth")) is not int or not 1 <= row["depth"] <= MAX_DEPTH
                or type(row.get("expires_at")) is not int or not isinstance(row.get("policy_revision"), str)
                or not valid_document(row.get("document"), response_id)):
            raise unavailable()
        if row["expires_at"] <= now():
            raise not_found()
        return row

    def put(self, turn, document, provider, model):
        deadline = {}
        if turn.deadline is not None:
            turn.deadline.check()
            deadline = {"deadline_ms": int(time.time() * 1000) + turn.deadline.remaining_ms()}
        result = self.operation("put", owner=turn.owner, id=turn.id, parent_id=turn.parent_id,
                                depth=turn.depth, provider=provider, model=model,
                                policy_revision=turn.revision, document=document, **deadline)
        if result != {"stored": True}:
            raise unavailable()

    def fail(self, turn):
        if self.operation("fail", owner=turn.owner, id=turn.id) != {"failed": True}:
            raise unavailable()

    def delete(self, owner, response_id):
        if not isinstance(response_id, str) or not _ID.fullmatch(response_id):
            raise not_found()
        if self.operation("delete", owner=owner, id=response_id) != {"deleted": True}:
            raise not_found()


def complete_body(body):
    from services.managed_turn import completed_envelope
    return (isinstance(body, dict) and body.get("object") == "response"
            and body.get("status") == "completed" and completed_envelope(body)
            and isinstance(body.get("output"), list)
            and all(isinstance(item, dict) and item.get("status", "completed") == "completed"
                    for item in body["output"]))


def valid_document(document, response_id):
    try:
        return (isinstance(document, dict) and set(document) == {"input", "response"}
                and isinstance(document["input"], list) and all(isinstance(item, dict) for item in document["input"])
                and complete_body(document["response"]) and document["response"].get("id") == response_id
                and len(canonical(document)) <= MAX_STATE_BYTES)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return False


def input_items(value):
    if isinstance(value, str):
        return [{"role": "user", "content": value}]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise GatewayError("invalid_request", "Hosted Responses input must be a string or an array of items.")
    return copy.deepcopy(value)


@dataclass
class HostedTurn:
    owner: str
    id: str
    parent_id: str | None
    depth: int
    revision: str
    input: list
    payload: dict
    store: ResponsesStateStore
    keep: bool
    accounting: object = None
    cancellation: object = None
    deadline: object = None
    finalized: bool = False


def prepare(payload):
    """Resolve retained input after authentication, before admission or dispatch."""
    opted = payload.get("gateway_state") is True
    parent = payload.get("previous_response_id")
    if not opted and not gateway_id(parent):
        return None
    retention = request_policy()
    if not retention.allows_content:
        raise GatewayError("retention_conflict", "Zero-content retention forbids hosted Responses state.")
    if opted and payload.get("store") is not True:
        raise GatewayError("invalid_request", "gateway_state requires store: true.")
    if opted and parent and not gateway_id(parent):
        raise GatewayError("invalid_request", "Hosted state requires a gateway-owned parent or full input.")
    store = current_app.extensions.get("responses_state_store")
    if store is None:
        raise unavailable()
    owner = principal_owner()
    history, depth = [], 1
    if gateway_id(parent):
        row = store.get(owner, parent)
        depth = row["depth"] + 1
        history = [*row["document"]["input"], *row["document"]["response"]["output"]]
    if depth > MAX_DEPTH:
        raise GatewayError("response_chain_limit", "Hosted Responses chains are limited to 16 generations.")
    history.extend(input_items(payload.get("input", "")))
    if len(canonical({"input": history, "response": {}})) > MAX_STATE_BYTES:
        raise GatewayError("response_state_too_large", "Hosted Responses state exceeds 1 MiB.")
    store.probe()
    cleaned = {key: copy.deepcopy(value) for key, value in payload.items()
               if key not in {"gateway_state", "previous_response_id"}}
    cleaned["input"] = history
    if opted:
        cleaned["store"] = False
    from services.managed_turn import idempotency_policy_revision
    revision = hashlib.sha256(canonical({"policy": idempotency_policy_revision(cleaned),
                                         "retention": retention.revision})).hexdigest()
    return HostedTurn(owner, ID_PREFIX + uuid.uuid4().hex, parent if gateway_id(parent) else None,
                      depth, revision, history, cleaned, store, opted)


def with_responses_state(dispatch):
    @wraps(dispatch)
    def wrapped(app, auth, metrics, proxy, payload, *args, **kwargs):
        turn = getattr(g, "hosted_responses_turn", None) if has_request_context() else None
        if turn is None or request.path != "/v1/responses":
            return dispatch(app, auth, metrics, proxy, payload, *args, **kwargs)
        from middleware.idempotency import mark_managed_handoff
        mark_managed_handoff()
        turn.accounting = getattr(g, "usage_context", None)
        result = dispatch(app, auth, metrics, proxy, turn.payload, *args, **kwargs)
        turn.cancellation = getattr(g, "gateway_cancellation", None)
        turn.deadline = current_deadline()
        return result
    return wrapped


def public_body(body, turn):
    return {**body, "id": turn.id, "store": True, "previous_response_id": turn.parent_id}


def persist(turn, body, headers):
    """Require terminal completion and settled accounting; never rebuild by generation."""
    if turn.finalized:
        return False
    turn.finalized = True
    if not complete_body(body):
        return False
    if (turn.accounting is None or not turn.accounting.finished or turn.accounting.ambiguous
            or turn.cancellation is not None and turn.cancellation.lost):
        return False
    if turn.deadline is not None:
        turn.deadline.check()
    body = public_body(body, turn)
    document = {"input": turn.input, "response": body}
    if not valid_document(document, turn.id):
        raise GatewayError("response_state_too_large", "Hosted Responses state exceeds 1 MiB.", 502)
    model = (headers.get("X-MultiLLM-Auto-Selected-Model") or headers.get("X-MultiLLM-Selected-Model")
             or getattr(turn.accounting, "selected", None) or turn.payload.get("model") or "unknown")
    provider = model.split(":", 1)[0] if ":" in model else "unknown"
    turn.store.put(turn, document, provider, str(body.get("model") or model))
    try:
        if turn.deadline is not None:
            turn.deadline.check()
        if turn.cancellation is not None and turn.cancellation.lost:
            raise GatewayError("response_outcome_unknown", "Hosted Responses completion could not be verified.", 502)
    except Exception:
        turn.store.fail(turn)
        raise
    return True


def rewrite_translated_response(body):
    """Small translator call site; persistence belongs to the route lifecycle."""
    turn = getattr(g, "hosted_responses_turn", None) if has_request_context() else None
    return public_body(body, turn) if turn is not None and turn.keep else body
