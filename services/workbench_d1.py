"""Workbench connection profiles and comparison results in D1, cached for 30 seconds.

Records belong to one owner. Reads use a 30-second process cache like automatic routes;
if D1 cannot be read, the last copy this process holds for that owner is returned with a
logged warning, or 503 when it never read one. Saves go straight to D1 and fail with 503
(409 at the per-owner limit, which the Worker checks atomically) instead of being kept
only in this process.
"""

import logging
import threading
import time

from error_handlers import APIError
from services import control_state_d1, intelligence_d1_store

logger = logging.getLogger(__name__)

ENDPOINT = "workbench"
CACHE_SECONDS = 30
MAX_CACHED_OWNERS = 256
_lock = threading.Lock()
_cache = {}


def using_d1():
    return control_state_d1.using_d1()


def unavailable():
    return APIError("Workbench storage is unavailable; nothing was changed", 503, {"error": "workbench_storage_unavailable"})


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _records(response, field, content):
    if not isinstance(response, dict) or set(response) != {"version", field} or not isinstance(response[field], list):
        raise ValueError("Invalid workbench response")
    for row in response[field]:
        if (not isinstance(row, dict) or set(row) != {"id", "created_at", content} or not isinstance(row["id"], str)
                or not _number(row["created_at"])):
            raise ValueError("Invalid workbench row")
    return response[field]


def _profiles(response):
    rows = _records(response, "profiles", "settings")
    if not all(isinstance(row["settings"], dict) and all(isinstance(value, str) for value in row["settings"].values())
               for row in rows):
        raise ValueError("Invalid profile settings")
    return [{"id": row["id"], "created_at": row["created_at"], **row["settings"]} for row in rows]


def _reports(response):
    rows = _records(response, "reports", "data")
    if not all(isinstance(row["data"], list) for row in rows):
        raise ValueError("Invalid comparison data")
    return rows


def _read(operation, owner, parse):
    now = time.monotonic()
    with _lock:
        cached = _cache.get((operation, owner))
    if cached is not None and now < cached[1]:
        return cached[0]
    try:
        records = parse(control_state_d1.call(ENDPOINT, operation, owner=owner))
    except Exception as error:
        logger.warning("Workbench %s could not be read from D1 (%s)%s", operation, control_state_d1.cause(error),
                       "; using the last copy" if cached is not None else "")
        if cached is not None:
            return cached[0]
        raise unavailable() from None
    with _lock:
        if len(_cache) >= MAX_CACHED_OWNERS:
            _cache.clear()
        _cache[(operation, owner)] = (records, now + CACHE_SECONDS)
    return records


def _save(operation, listing, owner, limit_message, **values):
    try:
        response = control_state_d1.call(ENDPOINT, operation, owner=owner, **values)
    except intelligence_d1_store.PrivateIntelligenceError as error:
        if error.status == 409 and error.code == "limit_reached":
            raise APIError(limit_message, status_code=409) from None
        logger.warning("Workbench %s could not be stored in D1 (%s)", operation, control_state_d1.cause(error))
        raise unavailable() from None
    except Exception as error:
        logger.warning("Workbench %s could not be stored in D1 (%s)", operation, control_state_d1.cause(error))
        raise unavailable() from None
    if response != {"version": 1, "stored": True}:
        raise unavailable()
    with _lock:
        _cache.pop((listing, owner), None)


def profiles(owner):
    return [dict(profile) for profile in _read("profiles", owner, _profiles)]


def save_profile(owner, identifier, profile, created_at):
    _save("save_profile", "profiles", owner,
          "Profile limit reached (50); export or manage existing settings before adding more",
          id=identifier, settings=profile, created_at=created_at)


def reports(owner):
    return list(_read("reports", owner, _reports))


def save_report(owner, identifier, rows, created_at):
    _save("save_report", "reports", owner, "Comparison history limit reached (100)",
          id=identifier, data=rows, created_at=created_at)


def reset_cache():
    with _lock:
        _cache.clear()
