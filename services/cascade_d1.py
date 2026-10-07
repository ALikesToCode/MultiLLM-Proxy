"""Private D1 cascade storage with a bounded last-known-good read cache."""

import copy
import logging
import threading
import time

from error_handlers import APIError
from services import intelligence_d1_store
from services.cascade_config import MAX_CASCADES, normalize_config

logger = logging.getLogger(__name__)
_lock = threading.Lock()
_cache = {"routes": None, "expires": 0.0}


def stored_routes():
    now = time.monotonic()
    with _lock:
        if _cache["routes"] is not None and now < _cache["expires"]:
            return copy.deepcopy(_cache["routes"])
    try:
        value = intelligence_d1_store.request_private_intelligence({"operation": "list"}, endpoint="cascades")
        if (not isinstance(value, dict) or set(value) != {"version", "cascades"} or type(value["version"]) is not int or value["version"] != 1
                or not isinstance(value["cascades"], list) or len(value["cascades"]) > MAX_CASCADES):
            raise ValueError("Invalid cascade storage response")
        routes = {item["name"]: item for item in map(normalize_config, value["cascades"])}
        expires = now + 30
    except Exception as error:
        logger.warning("Cascades could not be read from D1 (%s)", type(error).__name__)
        with _lock:
            routes = _cache["routes"] or {}
        expires = now + 10
    with _lock:
        _cache["routes"], _cache["expires"] = routes, expires
        return copy.deepcopy(routes)


def save_route(config):
    try:
        response = intelligence_d1_store.request_private_intelligence(
            {"operation": "put", "cascade": config}, endpoint="cascades")
        if response != {"version": 1, "stored": True}:
            raise ValueError("Invalid cascade storage acknowledgement")
    except Exception as error:
        logger.warning("Cascade could not be saved to D1 (%s)", type(error).__name__)
        raise APIError("Cascade storage is unavailable; the cascade was not saved", 503,
                       {"error": "cascade_storage_unavailable"}) from None
    with _lock:
        routes = dict(_cache["routes"] or {})
        if config["name"] in routes or len(routes) < MAX_CASCADES:
            routes[config["name"]] = copy.deepcopy(config)
        _cache["routes"], _cache["expires"] = routes, time.monotonic() + 30


def reset_cache():
    with _lock:
        _cache["routes"], _cache["expires"] = None, 0.0
