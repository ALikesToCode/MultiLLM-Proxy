"""Model status overrides (disabled models) in D1, cached for 30 seconds.

Routing reads every override from a process cache that is refreshed from D1 at most
every 30 seconds, like automatic routes, so another instance's change applies within
that time. If D1 cannot be read, the last stored copy stays in use (no overrides at all
before the first successful read) and a warning is logged; a save that cannot be stored
fails with 503 instead of being kept only in this process.
"""

import logging
import re
import threading
import time
from datetime import datetime, timezone

from error_handlers import APIError
from services import control_state_d1

logger = logging.getLogger(__name__)

ENDPOINT = "model_overrides"
CACHE_SECONDS = 30
FAILURE_CACHE_SECONDS = 10
STATUSES = frozenset({"available", "disabled"})
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")
_lock = threading.Lock()
_cache = {"overrides": None, "expires": 0.0}


def using_d1():
    return control_state_d1.using_d1()


def _overrides(value):
    if not isinstance(value, dict) or set(value) != {"version", "overrides"} or not isinstance(value["overrides"], list):
        raise ValueError("Invalid model override response")
    overrides = {}
    for row in value["overrides"]:
        if (not isinstance(row, dict) or set(row) != {"model_id", "status"} or not isinstance(row["model_id"], str)
                or row["status"] not in STATUSES):
            raise ValueError("Invalid model override row")
        overrides[row["model_id"]] = row["status"]
    return overrides


def overrides():
    """Stored statuses by model ID; never raises."""
    now = time.monotonic()
    with _lock:
        if _cache["overrides"] is not None and now < _cache["expires"]:
            return _cache["overrides"]
    try:
        current = _overrides(control_state_d1.call(ENDPOINT, "list"))
        expires = now + CACHE_SECONDS
    except Exception as error:
        logger.warning("Model overrides could not be read from D1 (%s); using the last stored copy",
                       control_state_d1.cause(error))
        with _lock:
            current = _cache["overrides"] if _cache["overrides"] is not None else {}
        # Retry soon, without adding a failing private call to every routed request.
        expires = now + FAILURE_CACHE_SECONDS
    with _lock:
        _cache["overrides"], _cache["expires"] = current, expires
    return current


def save(model_id, status):
    if not _MODEL_ID.fullmatch(model_id) or ":" not in model_id or status not in STATUSES:
        raise APIError("This model ID cannot be stored as an override", 400)
    unavailable = APIError("Model override storage is unavailable; the change was not saved", 503,
                           {"error": "model_override_storage_unavailable"})
    try:
        response = control_state_d1.call(ENDPOINT, "put", model_id=model_id, status=status,
                                         updated_at=datetime.now(timezone.utc).isoformat())
    except Exception as error:
        logger.warning("Model override could not be saved to D1 (%s)", control_state_d1.cause(error))
        raise unavailable from None
    if response != {"version": 1, "stored": True}:
        raise unavailable
    with _lock:
        current = dict(_cache["overrides"] or {})
        current[model_id] = status
        _cache["overrides"] = current
        # Keep the expiry: a cold cache still reads every other stored override on first use.


def reset_cache():
    with _lock:
        _cache["overrides"], _cache["expires"] = None, 0.0
