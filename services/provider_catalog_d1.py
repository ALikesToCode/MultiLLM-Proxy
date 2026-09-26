"""The last good model catalog per provider, kept in D1.

Discovery refetches provider catalogs, but a new Container used to start with an empty
catalog until its next refresh. In D1 mode every successful refresh stores that
provider's snapshot (compressed; the Worker splits it into chunks), and each process
keeps the snapshots in memory and checks D1 for newer ones at most every
REFRESH_SECONDS. A snapshot that cannot be stored stays in this process with a logged
warning; if D1 cannot be read, the last copy stays in use.

Rows are plain tuples (model_id, context_window, max_output_tokens, metadata_json);
ProviderCatalogService turns them into catalog models and sanitizes the metadata again.
"""

import base64
import binascii
import json
import logging
import re
import threading
import time
import zlib

from services import control_state_d1

logger = logging.getLogger(__name__)

ENDPOINT = "provider_catalog"
REFRESH_SECONDS = 60
FAILURE_SECONDS = 15
# A cold process waits this long for its first copy; later reads never wait on D1.
COLD_WAIT_SECONDS = 10
MAX_SNAPSHOT_CHARS = 240_000
MAX_DECODED_BYTES = 16 * 1024 * 1024
_PROVIDER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")
_TIMESTAMP = re.compile(r"[0-9T:.+\-Z]{10,40}\Z")
_lock = threading.Lock()
_refresh_lock = threading.Lock()


def _fresh_state(version=0):
    # The version only grows, so a catalog built from an earlier state is never reused.
    return {"snapshots": {}, "loaded": False, "expires": 0.0, "version": version}


_state = _fresh_state()


def using_d1():
    return control_state_d1.using_d1()


def encode(rows):
    payload = json.dumps([list(row) for row in rows], separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return base64.b64encode(zlib.compress(payload.encode("utf-8"), 9)).decode("ascii")


def _limit(value):
    return value is None or (type(value) is int and value > 0)


def decode(data):
    try:
        compressed = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Invalid catalog snapshot encoding") from None
    inflater = zlib.decompressobj()
    payload = inflater.decompress(compressed, MAX_DECODED_BYTES)
    if inflater.unconsumed_tail or not inflater.eof:
        raise ValueError("Catalog snapshot is truncated or too large")
    rows = json.loads(payload.decode("utf-8"))
    if not isinstance(rows, list):
        raise ValueError("Invalid catalog snapshot")
    decoded = []
    for row in rows:
        if (not isinstance(row, list) or len(row) != 4 or not isinstance(row[0], str) or not _MODEL_ID.fullmatch(row[0])
                or not _limit(row[1]) or not _limit(row[2]) or not (row[3] is None or isinstance(row[3], str))):
            raise ValueError("Invalid catalog snapshot row")
        decoded.append(tuple(row))
    return tuple(decoded)


def _listing(response):
    if not isinstance(response, dict) or set(response) != {"version", "snapshots"} or not isinstance(response["snapshots"], list):
        raise ValueError("Invalid catalog listing")
    listing = {}
    for row in response["snapshots"]:
        if (not isinstance(row, dict) or set(row) != {"provider", "updated_at"} or not isinstance(row["provider"], str)
                or not isinstance(row["updated_at"], str)):
            raise ValueError("Invalid catalog listing row")
        listing[row["provider"]] = row["updated_at"]
    return listing


def _snapshot(response, provider):
    if not isinstance(response, dict) or set(response) != {"version", "snapshot"}:
        raise ValueError("Invalid catalog snapshot response")
    snapshot = response["snapshot"]
    if snapshot is None:
        return None
    if (not isinstance(snapshot, dict) or set(snapshot) != {"provider", "updated_at", "data"}
            or snapshot["provider"] != provider or not isinstance(snapshot["updated_at"], str)
            or not isinstance(snapshot["data"], str)):
        raise ValueError("Invalid catalog snapshot")
    return snapshot["updated_at"], decode(snapshot["data"])


def _keep_newer(snapshots, provider, snapshot):
    current = snapshots.get(provider)
    if current is None or current[0] <= snapshot[0]:
        snapshots[provider] = snapshot
        return True
    return False


def snapshots():
    """({provider: (updated_at, rows)}, version); never raises."""
    with _lock:
        if time.monotonic() < _state["expires"]:
            return _state["snapshots"], _state["version"]
        cold = not _state["loaded"]
    # Only a process without any copy waits for a refresh another thread is running.
    if not _refresh_lock.acquire(timeout=COLD_WAIT_SECONDS if cold else 0):
        with _lock:
            return _state["snapshots"], _state["version"]
    try:
        with _lock:
            if time.monotonic() < _state["expires"]:
                return _state["snapshots"], _state["version"]
            known = {provider: snapshot[0] for provider, snapshot in _state["snapshots"].items()}
        started, fetched, expires = time.monotonic(), {}, None
        try:
            for provider, updated_at in _listing(control_state_d1.call(ENDPOINT, "list")).items():
                if known.get(provider, "") >= updated_at or not _PROVIDER.fullmatch(provider):
                    continue
                if time.monotonic() - started > COLD_WAIT_SECONDS:
                    expires = time.monotonic()  # Fetch the rest on the next read.
                    break
                snapshot = _snapshot(control_state_d1.call(ENDPOINT, "get", provider=provider), provider)
                if snapshot is not None:
                    fetched[provider] = snapshot
        except Exception as error:
            logger.warning("Provider catalog snapshots could not be read from D1 (%s); using the last copy",
                           control_state_d1.cause(error))
            expires = time.monotonic() + FAILURE_SECONDS
        with _lock:
            current = dict(_state["snapshots"])
            changed = [provider for provider, snapshot in fetched.items() if _keep_newer(current, provider, snapshot)]
            _state["snapshots"], _state["loaded"] = current, True
            _state["expires"] = expires if expires is not None else time.monotonic() + REFRESH_SECONDS
            _state["version"] += bool(changed)
            return _state["snapshots"], _state["version"]
    finally:
        _refresh_lock.release()


def save(provider, updated_at, rows):
    """Keep a refreshed snapshot in this process and store it in D1; False if it was not stored."""
    rows = tuple(tuple(row) for row in rows)
    with _lock:
        current = dict(_state["snapshots"])
        current[provider] = (updated_at, rows)
        _state["snapshots"] = current
        _state["version"] += 1
    try:
        data = encode(rows)
        if len(data) > MAX_SNAPSHOT_CHARS or not _PROVIDER.fullmatch(provider) or not _TIMESTAMP.fullmatch(updated_at):
            logger.warning("Provider catalog snapshot for %s is too large or malformed to store in D1 (%d characters)",
                           provider, len(data))
            return False
        response = control_state_d1.call(ENDPOINT, "put", provider=provider, updated_at=updated_at, data=data)
    except Exception as error:
        logger.warning("Provider catalog snapshot for %s could not be stored in D1 (%s); kept in this Container only",
                       provider, control_state_d1.cause(error))
        return False
    return response == {"version": 1, "stored": True}


def reset():
    """Forget every snapshot in this process, as a restart would."""
    global _state
    with _lock:
        _state = _fresh_state(_state["version"] + 1)
