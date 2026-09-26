"""Free-route cooldowns shared through D1 without a D1 round trip on the request path.

Cooldowns are read for every free-pool candidate, so this process answers from memory:
its own cooldowns plus the shared ones, refreshed from D1 by the background thread every
REFRESH_SECONDS while the free pool is in use. A new cooldown applies here at once and
is written to D1 on the next background tick; D1 keeps the later expiry when instances
disagree. Another instance's cooldown can take one refresh interval to arrive, so one
extra upstream attempt may reach a provider that is already cooling down. While D1 is
unavailable this process keeps its own cooldowns and the last shared copy.
"""

import logging
import math
import re
import threading
import time
from itertools import islice

from services import control_state_d1

logger = logging.getLogger(__name__)

ENDPOINT = "free_quotas"
REFRESH_SECONDS = 10
FAILURE_BACKOFF_SECONDS = 30
# The shared copy is refreshed only while free routes were used this recently.
ACTIVE_SECONDS = 300
MAX_WRITES = 32
MAX_PENDING = 1000
_SCOPE = re.compile(r"(?:provider|model):[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")
_lock = threading.Lock()


def _fresh_state():
    return {"cooldowns": {}, "pending": {}, "refreshed": None, "used": None, "retry_at": 0.0}


_state = _fresh_state()


def using_d1():
    return control_state_d1.using_d1()


def remaining(scope, now):
    """Seconds left on a cooldown, from memory; the first use wakes a refresh."""
    with _lock:
        _state["used"] = time.monotonic()
        until = _state["cooldowns"].get(scope)
        cold = _state["refreshed"] is None
    if cold:
        control_state_d1.wake()
    else:
        control_state_d1.ensure_running()
    return max(0, math.ceil(until - now)) if until else 0


def block(scope, until):
    with _lock:
        _state["cooldowns"][scope] = max(_state["cooldowns"].get(scope, 0.0), until)
        pending = _state["pending"]
        if _SCOPE.fullmatch(scope) and (scope in pending or len(pending) < MAX_PENDING):
            pending[scope] = max(pending.get(scope, 0.0), until)
    control_state_d1.wake()


def _stored(response, count):
    if response != {"version": 1, "stored": count}:
        raise ValueError("Invalid cooldown response")


def _cooldowns(response):
    if not isinstance(response, dict) or set(response) != {"version", "cooldowns"} or not isinstance(response["cooldowns"], list):
        raise ValueError("Invalid cooldown response")
    rows = {}
    for row in response["cooldowns"]:
        if (not isinstance(row, dict) or set(row) != {"scope", "blocked_until"} or not isinstance(row["scope"], str)
                or not isinstance(row["blocked_until"], (int, float)) or isinstance(row["blocked_until"], bool)):
            raise ValueError("Invalid cooldown row")
        rows[row["scope"]] = float(row["blocked_until"])
    return rows


def sync(final=False):
    """Write new cooldowns, then refresh the shared copy if it is due."""
    monotonic, now = time.monotonic(), time.time()
    with _lock:
        state = _state
        if monotonic < state["retry_at"] and not final:
            return
        writes = list(islice(state["pending"].items(), MAX_WRITES))
        refresh = not final and state["used"] is not None and monotonic - state["used"] <= ACTIVE_SECONDS and (
            state["refreshed"] is None or monotonic - state["refreshed"] >= REFRESH_SECONDS)
        if not writes and not refresh:
            return
        for scope, _ in writes:
            del state["pending"][scope]
    try:
        if writes:
            _stored(control_state_d1.call(ENDPOINT, "block", cooldowns=[
                {"scope": scope, "blocked_until": until} for scope, until in writes]), len(writes))
            writes = []
        shared = _cooldowns(control_state_d1.call(ENDPOINT, "list")) if refresh else {}
    except Exception as error:
        with _lock:
            if not control_state_d1.refused(error):
                for scope, until in writes:
                    state["pending"][scope] = max(state["pending"].get(scope, 0.0), until)
            state["retry_at"] = monotonic + FAILURE_BACKOFF_SECONDS
        logger.warning("Free-route cooldowns could not be synced with D1 (%s); using this Container's cooldowns",
                       control_state_d1.cause(error))
        return
    with _lock:
        cooldowns = state["cooldowns"]
        for scope, until in shared.items():
            cooldowns[scope] = max(cooldowns.get(scope, 0.0), until)
        if refresh:
            state["refreshed"] = monotonic
        for scope, until in list(cooldowns.items()):
            if until < now:
                del cooldowns[scope]


def reset():
    """Forget every cooldown in this process, as a restart would."""
    global _state
    with _lock:
        _state = _fresh_state()


control_state_d1.register(sync)
