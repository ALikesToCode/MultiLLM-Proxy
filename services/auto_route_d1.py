"""Automatic routes in the Worker's D1 database, reached through the private outbound handler.

Container disk is reset whenever the Container sleeps or is replaced, so operator edits live
in D1 whenever the Worker provides its durable store. Reads fall back to the last stored
copy, then to the seeded defaults, so a D1 outage never removes routing; a save that cannot
be stored fails instead of being kept only on local disk.
"""

import logging
import re
import threading
import time

from error_handlers import APIError
from services import intelligence_d1_store

logger = logging.getLogger(__name__)

CACHE_SECONDS = 30
FAILURE_CACHE_SECONDS = 10
_ROUTE_ID = re.compile(r"auto:[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")
_lock = threading.Lock()
_cache = {"routes": None, "expires": 0.0}


def using_d1():
    return intelligence_d1_store.using_d1()


def _routes(value):
    if not isinstance(value, dict) or set(value) != {"version", "routes"} or not isinstance(value["routes"], list):
        raise ValueError("Invalid auto route response")
    routes = {}
    for row in value["routes"]:
        if (not isinstance(row, dict) or set(row) != {"route_id", "candidates", "updated_at"}
                or not isinstance(row["route_id"], str) or not _ROUTE_ID.fullmatch(row["route_id"])
                or not isinstance(row["candidates"], list) or not row["candidates"]
                or not all(isinstance(item, str) and _MODEL_ID.fullmatch(item) for item in row["candidates"])
                or not isinstance(row["updated_at"], str)):
            raise ValueError("Invalid auto route row")
        routes[row["route_id"]] = (tuple(row["candidates"]), row["updated_at"])
    return routes


def stored_routes():
    """Stored routes by ID as (candidates, updated_at); never raises."""
    now = time.monotonic()
    with _lock:
        if _cache["routes"] is not None and now < _cache["expires"]:
            return _cache["routes"]
    try:
        routes = _routes(intelligence_d1_store.request_private_intelligence({"operation": "list"}, endpoint="auto_routes"))
        expires = now + CACHE_SECONDS
    except Exception as error:
        logger.warning("Auto routes could not be read from D1 (%s); using the last stored copy or defaults",
                       getattr(error, "code", None) or type(error).__name__)
        with _lock:
            routes = _cache["routes"] if _cache["routes"] is not None else {}
        # Retry soon, without adding a failing private call to every routed request.
        expires = now + FAILURE_CACHE_SECONDS
    with _lock:
        _cache["routes"], _cache["expires"] = routes, expires
    return routes


def save_route(route_id, candidates, updated_at):
    try:
        response = intelligence_d1_store.request_private_intelligence(
            {"operation": "put", "route_id": route_id, "candidates": list(candidates), "updated_at": updated_at},
            endpoint="auto_routes")
    except Exception as error:
        logger.warning("Auto route %s could not be saved to D1 (%s)", route_id,
                       getattr(error, "code", None) or type(error).__name__)
        raise APIError("Auto route storage is unavailable; the route was not saved", 503,
                       {"error": "auto_route_storage_unavailable"}) from None
    if response != {"version": 1, "stored": True}:
        raise APIError("Auto route storage is unavailable; the route was not saved", 503,
                       {"error": "auto_route_storage_unavailable"})
    with _lock:
        routes = dict(_cache["routes"] or {})
        routes[route_id] = (tuple(candidates), updated_at)
        _cache["routes"], _cache["expires"] = routes, time.monotonic() + CACHE_SECONDS


def reset_cache():
    with _lock:
        _cache["routes"], _cache["expires"] = None, 0.0
