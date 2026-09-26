"""Request usage shared through D1 without a D1 round trip on the request path.

In D1 mode each process admits requests against an in-memory ledger: the exact requests
it admitted itself in the last minute and day, plus a cached figure for the usage every
other ledger recorded (other Container instances, and this Container's earlier processes
before a restart). A background thread flushes this process's usage to D1 as atomic
per-minute and per-hour increments every RATE_LIMIT_SYNC_SECONDS (default 5) and, in the
same private call, refreshes the other ledgers' usage for the identities it is serving.
A flush carries an ID that D1 records with it, so a flush whose reply was lost and is
sent again is counted once.

Consistency: usage from another instance becomes visible here after at most one sync
interval plus a round trip, and its per-minute share is estimated from minute buckets.
A burst spread across instances, or the first seconds after a restart before the first
refresh, can therefore admit slightly more than a limit. Usage admitted in the last
interval before a crash may never reach D1. While D1 is unavailable, limits use this
process's own counts and the last shared figures, with a logged warning.
"""

import hashlib
import hmac
import logging
import os
import re
import threading
import time
import uuid
from collections import deque
from contextlib import contextmanager
from itertools import islice

from services import control_state_d1

logger = logging.getLogger(__name__)

ENDPOINT = "rate_limits"
MINUTE_SECONDS = 60
DAY_MINUTES = 24 * 60
DEFAULT_SYNC_SECONDS = 5
FAILURE_BACKOFF_SECONDS = 30
# Identities whose shared usage is refreshed: those that sent a request this recently.
ACTIVE_SECONDS = 120
# Shared figures older than this are ignored rather than trusted indefinitely.
REMOTE_MAX_AGE_SECONDS = 15 * 60
PRUNE_SECONDS = 600
RESERVATION_SECONDS = 2 * 3600
MAX_INCREMENTS = 12
MAX_READS = 16
MAX_PENDING = 10_000
FIGURES = ("current_requests", "current_tokens", "previous_requests", "previous_tokens", "day_requests")
_PROVIDER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_lock = threading.Lock()


class _Key:
    """One identity and provider: this process's own usage and the others' last figures."""

    __slots__ = ("recent", "day", "day_total", "remote", "used")

    def __init__(self):
        self.recent = {}  # reservation id -> [admitted_at, tokens] within the last minute
        self.day = deque()  # [minute, requests] for the last day
        self.day_total = 0
        self.remote = None  # (worker minute, figures, fetched_at)
        self.used = 0.0


def _fresh_state():
    return {"pid": os.getpid(), "instance": uuid.uuid4().hex, "keys": {}, "reservations": {}, "pending": {},
            "inflight": None, "next_id": 1, "next_sync": 0.0, "retry_at": 0.0, "last_call": 0.0, "last_prune": 0.0,
            "last_local_prune": 0.0, "dropped": 0}


_state = _fresh_state()


def _clock():
    return time.time()


def active():
    return control_state_d1.using_d1()


def sync_seconds():
    try:
        value = int(os.environ.get("RATE_LIMIT_SYNC_SECONDS", DEFAULT_SYNC_SECONDS))
    except (TypeError, ValueError):
        value = DEFAULT_SYNC_SECONDS
    return min(max(value, 1), 60)


def identity_key(identity):
    """A keyed hash, so D1 never holds usernames, key prefixes or client addresses."""
    secret = (os.environ.get("JWT_SECRET") or "").encode("utf-8")
    return hmac.new(secret, f"rate-limit\0{identity}".encode("utf-8"), hashlib.sha256).hexdigest()


def _current():
    # A forked child must not share its parent's ledger identity or counts.
    global _state
    if _state["pid"] != os.getpid():
        _state = _fresh_state()
    return _state


def _record(state, key, minute, requests, tokens):
    if not _PROVIDER.fullmatch(key[1]):
        return
    item = (key[0], key[1], minute)
    pending = state["pending"]
    if item not in pending and len(pending) >= MAX_PENDING:
        state["dropped"] += 1
        if state["dropped"] in (1, 100) or state["dropped"] % 10_000 == 0:
            logger.warning("Shared request usage buffer is full; %d increments were not sent to D1", state["dropped"])
        return
    counts = pending.setdefault(item, [0, 0])
    counts[0] += requests
    counts[1] += tokens


def _unknown(entry, now):
    return entry.remote is None or now - entry.remote[2] > REMOTE_MAX_AGE_SECONDS


def _remote_usage(entry, now):
    if _unknown(entry, now):
        return 0, 0, 0
    worker_minute, figures, _ = entry.remote
    # Sliding-window estimate from the minute buckets: all of this minute and the part of
    # the previous minute that still falls inside the last 60 seconds.
    minute, weight = int(now // MINUTE_SECONDS), 1 - (now % MINUTE_SECONDS) / MINUTE_SECONDS
    if worker_minute == minute:
        requests = figures["current_requests"] + figures["previous_requests"] * weight
        tokens = figures["current_tokens"] + figures["previous_tokens"] * weight
    elif worker_minute == minute - 1:
        requests, tokens = figures["current_requests"] * weight, figures["current_tokens"] * weight
    else:
        requests = tokens = 0
    return round(requests), round(tokens), figures["day_requests"]


class Usage:
    """The ledger while the caller holds it for one admission decision."""

    def __init__(self, state, now):
        self._state, self.now, self.unknown = state, now, False

    def _entry(self, identity, provider):
        key = (identity_key(identity), provider)
        entry = self._state["keys"].get(key)
        if entry is None:
            entry = self._state["keys"][key] = _Key()
        return key, entry

    def window(self, identity, provider, *, exclude=None):
        """(requests in the last minute, tokens in the last minute, requests in the last day)."""
        _, entry = self._entry(identity, provider)
        entry.used = self.now
        self.unknown = self.unknown or _unknown(entry, self.now)
        cutoff, requests, tokens = self.now - MINUTE_SECONDS, 0, 0
        for reservation, (admitted_at, reserved_tokens) in list(entry.recent.items()):
            if admitted_at < cutoff:
                del entry.recent[reservation]
            elif reservation != exclude:
                requests += 1
                tokens += reserved_tokens
        oldest = int(self.now // MINUTE_SECONDS) - DAY_MINUTES
        while entry.day and entry.day[0][0] <= oldest:
            entry.day_total -= entry.day.popleft()[1]
        day = entry.day_total - (1 if exclude is not None else 0)
        shared_requests, shared_tokens, shared_day = _remote_usage(entry, self.now)
        return requests + shared_requests, tokens + shared_tokens, day + shared_day

    def admit(self, identity, provider, tokens):
        key, entry = self._entry(identity, provider)
        reservation = self._state["next_id"]
        self._state["next_id"] += 1
        entry.recent[reservation] = [self.now, tokens]
        minute = int(self.now // MINUTE_SECONDS)
        if entry.day and entry.day[-1][0] == minute:
            entry.day[-1][1] += 1
        else:
            entry.day.append([minute, 1])
        entry.day_total += 1
        self._state["reservations"][reservation] = (key, self.now)
        _record(self._state, key, minute, 1, tokens)
        return reservation

    def owns(self, reservation, identity, provider):
        held = self._state["reservations"].get(reservation)
        return held is not None and held[0] == (identity_key(identity), provider)

    def settle(self, reservation, tokens):
        key, _ = self._state["reservations"][reservation]
        entry = self._state["keys"][key]
        previous = entry.recent.get(reservation, (0, 0))[1]
        entry.recent[reservation] = [self.now, tokens]
        if tokens > previous:
            _record(self._state, key, int(self.now // MINUTE_SECONDS), 0, tokens - previous)


@contextmanager
def transaction():
    """Hold the ledger for one check-and-admit, so concurrent requests cannot both pass a limit."""
    with _lock:
        usage = Usage(_current(), _clock())
        yield usage
    control_state_d1.ensure_running()
    if usage.unknown:
        # Fetch the other ledgers' usage for a new or long-idle identity now, not on the next interval.
        control_state_d1.wake()


def _figures(response, reads):
    if (not isinstance(response, dict) or set(response) != {"version", "minute", "usage"}
            or type(response["minute"]) is not int or not isinstance(response["usage"], list)
            or len(response["usage"]) != len(reads)):
        raise ValueError("Invalid usage response")
    figures = {}
    for row, key in zip(response["usage"], reads):
        if (not isinstance(row, dict) or set(row) != {"identity", "provider", *FIGURES}
                or (row["identity"], row["provider"]) != key
                or any(type(row[name]) is not int or row[name] < 0 for name in FIGURES)):
            raise ValueError("Invalid usage row")
        figures[key] = {name: row[name] for name in FIGURES}
    return response["minute"], figures


def _prune(state, now):
    """Drop expired reservations and identities with no usage left in the day window."""
    state["last_local_prune"] = now
    for reservation, (_, reserved_at) in list(state["reservations"].items()):
        if now - reserved_at > RESERVATION_SECONDS:
            del state["reservations"][reservation]
    oldest = int(now // MINUTE_SECONDS) - DAY_MINUTES
    for key, entry in list(state["keys"].items()):
        while entry.day and entry.day[0][0] <= oldest:
            entry.day_total -= entry.day.popleft()[1]
        if not entry.day and now - entry.used > ACTIVE_SECONDS:
            del state["keys"][key]


def _refresh_order(state, key):
    remote = state["keys"][key].remote
    return remote[2] if remote is not None else 0.0


def sync(final=False):
    """Flush pending usage and refresh the others' usage in at most one private call."""
    now = _clock()
    with _lock:
        state = _current()
        if now - state["last_local_prune"] >= PRUNE_SECONDS:
            _prune(state, now)
        if now < state["retry_at"] and not final:
            return
        interval = sync_seconds()
        reads = [] if final else sorted(
            (key for key, entry in state["keys"].items()
             if now - entry.used <= ACTIVE_SECONDS and _PROVIDER.fullmatch(key[1])
             and (entry.remote is None or now - entry.remote[2] >= interval)),
            key=lambda key: _refresh_order(state, key))[:MAX_READS]
        # A new or long-idle identity is fetched at once (at most once a second), not on the next interval.
        unknown = any(_unknown(state["keys"][key], now) for key in reads) and now - state["last_call"] >= 1
        if not (final or now >= state["next_sync"] or unknown):
            return
        if state["inflight"] is None and state["pending"]:
            batch = list(islice(state["pending"].items(), MAX_INCREMENTS))
            for item, _ in batch:
                del state["pending"][item]
            state["inflight"] = (uuid.uuid4().hex, [
                {"identity": identity, "provider": provider, "minute": minute, "requests": requests, "tokens": tokens}
                for (identity, provider, minute), (requests, tokens) in batch])
        flush_id, increments = state["inflight"] or (None, [])
        if not increments and not reads:
            return
        prune = not final and now - state["last_prune"] >= PRUNE_SECONDS
        state["last_call"] = now
        instance = state["instance"]
    try:
        response = control_state_d1.call(ENDPOINT, "sync", instance=instance, flush_id=flush_id, increments=increments,
                                         read=[{"identity": identity, "provider": provider} for identity, provider in reads],
                                         prune=prune)
        worker_minute, figures = _figures(response, reads)
    except Exception as error:
        with _lock:
            if state["inflight"] is not None and state["inflight"][0] == flush_id and control_state_d1.refused(error):
                state["inflight"] = None  # The Worker rejected it; sending it again cannot succeed.
            state["retry_at"] = now + FAILURE_BACKOFF_SECONDS
        logger.warning("Request usage could not be synced with D1 (%s); limits use this Container's own counts "
                       "and the last shared figures", control_state_d1.cause(error))
        return
    with _lock:
        if state["inflight"] is not None and state["inflight"][0] == flush_id:
            state["inflight"] = None
        for key, values in figures.items():
            entry = state["keys"].get(key)
            if entry is not None:
                entry.remote = (worker_minute, values, now)
        if prune:
            state["last_prune"] = now
        # A backlog larger than one call carries is sent on the next tick.
        state["next_sync"] = now if len(state["pending"]) >= MAX_INCREMENTS else now + interval


def reset():
    """Forget all usage in this process, as a restart would."""
    global _state
    with _lock:
        _state = _fresh_state()


control_state_d1.register(sync)
