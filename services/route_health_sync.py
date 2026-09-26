"""Write-behind persistence of route health to D1, off the request path.

A daemon thread loads the stored figures once when the Container starts, so routing and the
status page survive sleep and replacement, then writes changed entries in batches every
ROUTE_HEALTH_FLUSH_SECONDS together with the public status snapshot. A failed write keeps
the entries marked as changed for the next pass; no request ever waits on D1 here.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

from services import route_health_d1
from services.route_health import RouteHealth, iso_time_ms
from services.status_snapshot import build_public_status

logger = logging.getLogger(__name__)

# While the Container is awake the snapshot is rewritten at least this often, so the page
# served during sleep shows when the Container last reported.
SNAPSHOT_REFRESH_SECONDS = 600
# Below worker/route-health-d1.mjs MAX_SNAPSHOT_BYTES and the private transport's body limit.
MAX_SNAPSHOT_BYTES = 180_000
_LOAD_ATTEMPTS_BEFORE_WRITING = 3
_MAX_PASSES = 16

_lock = threading.Lock()
_state: dict[str, Any] = {"thread": None, "loaded": False, "load_attempts": 0, "snapshot_at": 0.0}
_stop = threading.Event()


def flush_seconds() -> int:
    try:
        value = int(os.environ.get("ROUTE_HEALTH_FLUSH_SECONDS", "60"))
    except (TypeError, ValueError):
        return 60
    return min(3600, max(10, value))


def enabled() -> bool:
    if os.environ.get("ROUTE_HEALTH_PERSIST", "true").strip().lower() in {"0", "false", "no", "off"}:
        return False
    try:
        return route_health_d1.using_d1()
    except Exception:  # noqa: BLE001 - an invalid backend setting disables persistence.
        return False


def bounded_snapshot(snapshot: dict) -> dict:
    """Drop the last routes until the document fits the Worker's snapshot limit."""
    routes = list(snapshot["routes"])
    while routes and len(json.dumps({**snapshot, "routes": routes}, separators=(",", ":"))) > MAX_SNAPSHOT_BYTES:
        routes.pop()
    return {**snapshot, "routes": routes}


def load() -> bool:
    """Merge the stored rows into memory once."""
    with _lock:
        if _state["loaded"]:
            return True
        _state["load_attempts"] += 1
    try:
        merged = RouteHealth.merge_rows(route_health_d1.list_rows())
    except Exception as error:  # noqa: BLE001 - storage transports vary.
        logger.warning("Route health could not be read from D1 (%s)",
                       getattr(error, "code", None) or type(error).__name__)
        return False
    with _lock:
        _state["loaded"] = True
    logger.info("Loaded %d route health entries from D1", merged)
    return True


def flush(*, force_snapshot: bool = False, now: float | None = None) -> bool:
    """Write changed entries, then the status snapshot when anything changed or it is old."""
    if not enabled():
        return False
    with _lock:
        ready = _state["loaded"] or _state["load_attempts"] >= _LOAD_ATTEMPTS_BEFORE_WRITING
    if not ready:
        # Writing before the stored rows are merged would replace their older samples.
        return False
    current_time = time.time() if now is None else now
    wrote_rows = False
    for _ in range(_MAX_PASSES):
        rows = RouteHealth.dirty_rows(route_health_d1.MAX_ROWS_PER_PUT)
        if not rows:
            break
        try:
            route_health_d1.put_rows(rows)
        except Exception as error:  # noqa: BLE001 - keep the rows for the next pass.
            logger.warning("Route health could not be written to D1 (%s)",
                           getattr(error, "code", None) or type(error).__name__)
            return False
        RouteHealth.mark_stored(rows)
        wrote_rows = True
        if len(rows) < route_health_d1.MAX_ROWS_PER_PUT:
            break
    with _lock:
        stale = current_time - _state["snapshot_at"] >= SNAPSHOT_REFRESH_SECONDS
    if not (wrote_rows or force_snapshot or stale):
        return True
    try:
        route_health_d1.put_snapshot(bounded_snapshot(build_public_status(now=current_time)),
                                     iso_time_ms(current_time))
    except Exception as error:  # noqa: BLE001 - the next pass retries.
        logger.warning("Status snapshot could not be written to D1 (%s)",
                       getattr(error, "code", None) or type(error).__name__)
        return False
    with _lock:
        _state["snapshot_at"] = current_time
    return True


def _run() -> None:
    load()
    while not _stop.wait(flush_seconds()):
        try:
            if not _state["loaded"]:
                load()
            flush()
        except Exception as error:  # noqa: BLE001 - the writer must keep running.
            logger.warning("Route health writer pass failed (%s)", type(error).__name__)


def start_background() -> bool:
    """Start the writer once per process when the Worker's D1 store is available."""
    if not enabled():
        return False
    with _lock:
        thread = _state["thread"]
        if thread is not None and thread.is_alive():
            return True
        _stop.clear()
        thread = threading.Thread(target=_run, daemon=True, name="route-health-writer")
        _state["thread"] = thread
    thread.start()
    return True


def reset() -> None:
    """Stop the writer and forget load state, for tests."""
    _stop.set()
    with _lock:
        thread = _state["thread"]
        _state.update(thread=None, loaded=False, load_attempts=0, snapshot_at=0.0)
    if thread is not None and thread.is_alive():
        thread.join(timeout=1)
