"""Private, single-submission access to the Worker's durable intelligence store."""

import json
import logging
import os
import queue
import re
import threading
import time
import uuid

import requests
from requests.adapters import HTTPAdapter

from services.intelligence_contract import GatewayError
from services.intelligence_policy import DEFAULT_POLICY, validate_policy

logger = logging.getLogger(__name__)

_ENDPOINTS = {
    "store": "http://intelligence.internal/v1/store",
    "auth": "http://intelligence.internal/v1/auth",
    "users": "http://intelligence.internal/v1/users",
    "auto_routes": "http://intelligence.internal/v1/auto-routes",
    # Control-plane state; see services/control_state_d1.py.
    "rate_limits": "http://intelligence.internal/v1/state/limits",
    "login_attempts": "http://intelligence.internal/v1/state/login",
    "model_overrides": "http://intelligence.internal/v1/state/models",
    "free_quotas": "http://intelligence.internal/v1/state/quotas",
    "workbench": "http://intelligence.internal/v1/state/workbench",
    "provider_catalog": "http://intelligence.internal/v1/state/catalog",
    "route_health": "http://intelligence.internal/v1/route-health",
    "usage": "http://intelligence.internal/v1/usage",
}
_MAX_BYTES = 262144
_TIMEOUT = (2, 3)
_DEADLINE_SECONDS = 5
# Every authenticated request waits on an account lookup, and the first call after
# the Container or D1 has been idle can take several seconds. Give it room instead
# of failing a valid key.
_ENDPOINT_LIMITS = {"users": ((3, 8), 10)}
_TRANSPORT_SLOTS = threading.BoundedSemaphore(16)
# A worker thread holds its slot until the private call finishes, up to the transport
# timeout, even after its caller gave up. Account reads authenticate every request, so they
# get their own slots: a burst of them cannot take the chat store's reserve and settle
# slots, and store calls cannot starve authentication.
_ENDPOINT_SLOTS = {"users": threading.BoundedSemaphore(8), "auto_routes": threading.BoundedSemaphore(4)}
# Background usage and cooldown syncs run one at a time. Login throttling and the model
# override reads that routing waits on keep their own slots, so a stalled sync or catalog
# download cannot delay them; admin-only workbench and catalog state share a few.
_ADMIN_STATE_SLOTS = threading.BoundedSemaphore(4)
_ENDPOINT_SLOTS.update({
    "rate_limits": threading.BoundedSemaphore(2),
    "free_quotas": threading.BoundedSemaphore(2),
    "login_attempts": threading.BoundedSemaphore(4),
    "model_overrides": threading.BoundedSemaphore(2),
    "workbench": _ADMIN_STATE_SLOTS,
    "provider_catalog": _ADMIN_STATE_SLOTS,
    "route_health": threading.BoundedSemaphore(2),
    "usage": threading.BoundedSemaphore(4),
})
_SLOW_CALL_SECONDS = 2.0
_STATS_LOCK = threading.Lock()
_STATS = {}
_RESERVATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_MAX_INTEGER = 2**53 - 1
_KINDS = frozenset({"chat", "transcriptions", "speech", "embeddings"})


def _record(endpoint, *, exhausted=False, failed=False, elapsed=None):
    with _STATS_LOCK:
        stats = _STATS.setdefault(endpoint, {"calls": 0, "failures": 0, "slot_exhausted": 0, "slow_calls": 0, "slowest_ms": 0})
        if exhausted:
            stats["slot_exhausted"] += 1
            count = stats["slot_exhausted"]
        else:
            stats["calls"] += 1
            stats["failures"] += int(failed)
            if elapsed is not None:
                stats["slowest_ms"] = max(stats["slowest_ms"], round(elapsed * 1000))
                stats["slow_calls"] += int(elapsed >= _SLOW_CALL_SECONDS)
    if exhausted:
        logger.warning("Private %s transport has no free slot (%d refusals since start)", endpoint, count)
    elif elapsed is not None and elapsed >= _SLOW_CALL_SECONDS:
        logger.warning("Private %s call took %d ms", endpoint, round(elapsed * 1000))


def transport_stats():
    """Per-endpoint private call counts, slot refusals and latency since the process started."""
    with _STATS_LOCK:
        return {endpoint: dict(stats) for endpoint, stats in _STATS.items()}


def storage_unavailable():
    return GatewayError(
        "intelligence_store_unavailable",
        "The durable intelligence store is unavailable; an uncertain submission must not be replayed.",
        503,
    )


class PrivateIntelligenceError(Exception):
    """A bounded remote code and status, without the remote error message."""

    def __init__(self, status, code):
        super().__init__("The private intelligence request was rejected.")
        self.status, self.code = status, code


def using_d1():
    backend = os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip()
    if backend not in {"", "d1"}:
        raise storage_unavailable()
    return backend == "d1"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Invalid JSON constant")


def _decode_response(response, stopped, deadline, success_statuses):
    length = response.headers.get("Content-Length")
    if length is not None and (
        not length.isascii() or not length.isdecimal() or int(length) > _MAX_BYTES
    ):
        raise storage_unavailable()
    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
        raise storage_unavailable()
    if (
        response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise storage_unavailable()
    body = bytearray()
    for chunk in response.iter_content(chunk_size=4096):
        if stopped.is_set() or time.monotonic() >= deadline:
            raise storage_unavailable()
        if len(body) + len(chunk) > _MAX_BYTES:
            raise storage_unavailable()
        body.extend(chunk)
    payload = json.loads(
        body.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if (
        not isinstance(payload, dict)
        or type(payload.get("version")) is not int
        or payload["version"] != 1
    ):
        raise storage_unavailable()
    if response.status_code not in success_statuses:
        error = payload.get("error")
        if (
            not isinstance(error, dict)
            or not isinstance(error.get("code"), str)
            or not _ERROR_CODE.fullmatch(error["code"])
        ):
            raise storage_unavailable()
        raise PrivateIntelligenceError(response.status_code, error["code"])
    if "error" in payload:
        raise storage_unavailable()
    return payload


def _submit(url, body, stopped, deadline, results, slots, success_statuses, timeout=_TIMEOUT):
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            if stopped.is_set() or time.monotonic() >= deadline:
                return
            with session.post(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                result = _decode_response(response, stopped, deadline, success_statuses)
        results.put_nowait((True, result))
    except Exception as error:
        failure = (
            error
            if isinstance(error, (GatewayError, PrivateIntelligenceError))
            else storage_unavailable()
        )
        results.put_nowait((False, failure))
    finally:
        slots.release()


def request_private_intelligence(payload, *, endpoint="store"):
    """Wait once for an allowlisted private endpoint; never replay uncertainty.

    A bounded daemon worker also limits the caller's wait when response headers
    or bytes arrive too slowly for Requests' inactivity timeout to expire.
    """
    if (
        not isinstance(endpoint, str)
        or endpoint not in _ENDPOINTS
        or not isinstance(payload, dict)
    ):
        raise storage_unavailable()
    try:
        body = json.dumps(
            {**payload, "version": 1}, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise storage_unavailable() from None
    slots = _ENDPOINT_SLOTS.get(endpoint, _TRANSPORT_SLOTS)
    if len(body) > _MAX_BYTES:
        raise storage_unavailable()
    if not slots.acquire(blocking=False):
        _record(endpoint, exhausted=True)
        raise storage_unavailable()
    stopped, results = threading.Event(), queue.Queue(maxsize=1)
    timeout, deadline_seconds = _ENDPOINT_LIMITS.get(endpoint, (_TIMEOUT, _DEADLINE_SECONDS))
    deadline = time.monotonic() + deadline_seconds
    worker = threading.Thread(
        target=_submit,
        args=(
            _ENDPOINTS[endpoint],
            body,
            stopped,
            deadline,
            results,
            slots,
            (200, 201) if endpoint == "auth" else (200,),
            timeout,
        ),
        daemon=True,
        name="intelligence-store",
    )
    try:
        worker.start()
    except Exception:
        slots.release()
        raise storage_unavailable() from None
    started = time.monotonic()
    try:
        success, result = results.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        _record(endpoint, failed=True, elapsed=time.monotonic() - started)
        raise storage_unavailable() from None
    finally:
        stopped.set()
    _record(endpoint, failed=not success, elapsed=time.monotonic() - started)
    if not success:
        raise result from None
    return result


def _store_request(operation, field, **values):
    try:
        response = request_private_intelligence({"operation": operation, **values})
    except PrivateIntelligenceError as error:
        if (
            operation == "reserve"
            and error.status == 429
            and error.code == "allowance_exhausted"
        ):
            raise GatewayError(
                "allowance_exhausted",
                "The request exceeds the available gateway allowance.",
                429,
                retryable=True,
                retry_after="60",
            ) from None
        raise storage_unavailable() from None
    if set(response) != {"version", field}:
        raise storage_unavailable()
    return response[field]


def _integer(value, minimum):
    return type(value) is int and minimum <= value <= _MAX_INTEGER


class D1IntelligenceStore:
    @classmethod
    def seed(cls, document):
        policy = validate_policy(document)
        inserted = _store_request("seed", "inserted", policy=policy)
        if type(inserted) is not bool:
            raise storage_unavailable()
        return inserted

    @classmethod
    def policy(cls):
        document = _store_request("policy", "policy")
        if document is None:
            seed = os.environ.get("INTELLIGENCE_POLICY_JSON")
            if not seed:
                return validate_policy(DEFAULT_POLICY)
            try:
                cls.seed(json.loads(seed))
            except (TypeError, ValueError, RecursionError):
                raise storage_unavailable() from None
            # A concurrent replica may have won the insert. Always use the
            # stored policy, and never spin or use an unpersisted seed.
            document = _store_request("policy", "policy")
        try:
            return validate_policy(document)
        except (TypeError, ValueError, RecursionError):
            raise storage_unavailable() from None

    @classmethod
    def reserve(cls, principal, amount, *, kind="chat"):
        if (
            not isinstance(principal, str)
            or not 1 <= len(principal) <= 256
            or re.search(r"[\x00-\x1f\x7f]", principal)
            or not _integer(amount, 1)
            or not isinstance(kind, str)
            or kind not in _KINDS
            or (kind != "chat" and amount != 1)
        ):
            raise storage_unavailable()
        reservation = uuid.uuid4().hex
        returned = _store_request(
            "reserve",
            "id",
            id=reservation,
            principal=principal,
            amount=amount,
            kind=kind,
        )
        if returned != reservation:
            raise storage_unavailable()
        return reservation

    @classmethod
    def settle(cls, reservation, used, complete):
        if (
            not isinstance(reservation, str)
            or not _RESERVATION_ID.fullmatch(reservation)
            or not _integer(used, 0)
            or type(complete) is not bool
        ):
            raise storage_unavailable()
        settled = _store_request(
            "settle", "settled", id=reservation, used=used, complete=complete
        )
        if type(settled) is not bool:
            raise storage_unavailable()
        return settled
