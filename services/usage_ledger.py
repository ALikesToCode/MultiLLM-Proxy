"""Write-behind usage ledger for billable requests.

Requests never wait on storage: `record` appends to a bounded in-memory buffer and a
background thread flushes batches every few seconds, when a batch fills, and at process
exit. A full buffer drops the newest row and counts it. A failed flush keeps its batch
and retries it under the same batch ID, which the store applies at most once. Raw rows
are pruned after `USAGE_LEDGER_RAW_RETENTION_DAYS`; daily totals are kept longer.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from services import usage_store

logger = logging.getLogger(__name__)

MAX_BATCH_BYTES = 200_000
PRUNE_BATCH = 5000


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def enabled() -> bool:
    return os.environ.get("USAGE_LEDGER_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def utc_timestamp(moment: Optional[datetime] = None) -> str:
    """UTC with millisecond precision and a Z suffix, the format the Worker accepts."""
    moment = (moment or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class UsageLedger:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._wake = threading.Event()
        self._buffer: deque = deque()
        self._pending: Optional[dict] = None
        self._thread: Optional[threading.Thread] = None
        self._listeners: list[tuple[Callable, Callable]] = []
        self._store = None
        self._next_prune = 0.0
        self._stats = {"recorded": 0, "dropped": 0, "failed_flushes": 0, "last_flush_at": None, "last_error": None}

    # Configuration is read per call so a deployment's environment and tests apply at once.
    @staticmethod
    def batch_size() -> int:
        return _env_int("USAGE_LEDGER_BATCH_SIZE", 200, 1, 500)

    @staticmethod
    def max_buffer() -> int:
        return _env_int("USAGE_LEDGER_MAX_BUFFER", 10000, 1, 1_000_000)

    @staticmethod
    def flush_seconds() -> float:
        return _env_float("USAGE_LEDGER_FLUSH_SECONDS", 5.0, 0.05, 300.0)

    @staticmethod
    def max_attempts() -> int:
        return _env_int("USAGE_LEDGER_MAX_ATTEMPTS", 12, 1, 1000)

    def store(self):
        if self._store is None or self._store.backend != usage_store.selected_backend():
            self._store = usage_store.open_store()
        return self._store

    def add_listener(self, on_flushed: Callable[[list], None], on_dropped: Callable[[list], None]) -> None:
        self._listeners.append((on_flushed, on_dropped))

    def _notify(self, index: int, rows: list) -> None:
        for listener in self._listeners:
            try:
                listener[index](rows)
            except Exception as error:  # A listener must never stop the ledger.
                logger.warning("Usage ledger listener failed (%s)", type(error).__name__)

    def record(self, row: dict) -> bool:
        """Queue one row; returns False when the ledger is disabled or full.

        Listeners hear about every row exactly once: stored or dropped.
        """
        if not enabled():
            self._notify(1, [row])
            return False
        full = False
        with self._lock:
            if len(self._buffer) >= self.max_buffer():
                self._stats["dropped"] += 1
                dropped = True
            else:
                self._buffer.append(row)
                dropped = False
                full = len(self._buffer) >= self.batch_size()
        if dropped:
            logger.warning("Usage ledger buffer is full; a row was dropped (%d dropped since start)",
                           self._stats["dropped"])
            self._notify(1, [row])
            return False
        self._ensure_thread()
        if full:
            self._wake.set()
        return True

    def _ensure_thread(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._run, name="usage-ledger", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while True:
            self._wake.wait(self.flush_seconds())
            self._wake.clear()
            try:
                self.flush_once()
                self._maybe_prune()
            except Exception as error:  # The thread must survive any storage fault.
                logger.warning("Usage ledger flush failed (%s)", type(error).__name__)

    def _take_batch(self) -> Optional[dict]:
        with self._lock:
            if self._pending is not None:
                return self._pending
            if not self._buffer:
                return None
            rows, size = [], 0
            while self._buffer and len(rows) < self.batch_size():
                row_size = len(json.dumps(self._buffer[0], separators=(",", ":"))) + 1
                if rows and size + row_size > MAX_BATCH_BYTES:
                    break
                rows.append(self._buffer.popleft())
                size += row_size
            self._pending = {"id": uuid.uuid4().hex, "rows": rows, "attempts": 0, "retry_at": 0.0}
            return self._pending

    def flush_once(self) -> int:
        """Send one batch; returns the number of rows stored."""
        with self._flush_lock:
            batch = self._take_batch()
            if batch is None or time.monotonic() < batch["retry_at"]:
                return 0
            try:
                self.store().record(batch["id"], batch["rows"])
            except Exception as error:
                batch["attempts"] += 1
                self._stats["failed_flushes"] += 1
                self._stats["last_error"] = str(error)[:120] or type(error).__name__
                if batch["attempts"] >= self.max_attempts():
                    with self._lock:
                        self._pending = None
                        self._stats["dropped"] += len(batch["rows"])
                    logger.warning("Usage ledger dropped %d rows after %d failed flushes (%s)",
                                   len(batch["rows"]), batch["attempts"], self._stats["last_error"])
                    self._notify(1, batch["rows"])
                else:
                    batch["retry_at"] = time.monotonic() + min(60.0, self.flush_seconds() * 2 ** batch["attempts"])
                    logger.warning("Usage ledger flush failed (%s); retrying the batch", self._stats["last_error"])
                return 0
            with self._lock:
                self._pending = None
                self._stats["recorded"] += len(batch["rows"])
                self._stats["last_flush_at"] = utc_timestamp()
            self._notify(0, batch["rows"])
            return len(batch["rows"])

    def flush(self, timeout: float = 5.0) -> bool:
        """Flush everything now, retrying failures until the deadline; True when empty."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._pending is None and not self._buffer:
                    return True
                pending = self._pending
            if pending is not None:
                pending["retry_at"] = 0.0
            if not self.flush_once():
                time.sleep(0.05)
        with self._lock:
            return self._pending is None and not self._buffer

    def _maybe_prune(self) -> None:
        now = time.monotonic()
        if now < self._next_prune:
            return
        self._next_prune = now + _env_int("USAGE_LEDGER_PRUNE_INTERVAL_SECONDS", 3600, 60, 7 * 86400)
        self.prune()

    def prune(self) -> dict:
        raw_days = _env_int("USAGE_LEDGER_RAW_RETENTION_DAYS", 30, 1, 3650)
        rollup_days = _env_int("USAGE_LEDGER_ROLLUP_RETENTION_DAYS", 400, 1, 36500)
        today = datetime.now(timezone.utc)
        events_before = utc_timestamp(today - timedelta(days=raw_days))
        rollups_before = (today - timedelta(days=rollup_days)).strftime("%Y-%m-%d")
        totals = {"events": 0, "batches": 0, "rollups": 0}
        for _ in range(20):
            try:
                pruned = self.store().prune(events_before, rollups_before, PRUNE_BATCH)
            except Exception as error:
                logger.warning("Usage ledger prune failed (%s)", type(error).__name__)
                break
            for name in totals:
                totals[name] += int(pruned.get(name) or 0)
            if max(int(pruned.get(name) or 0) for name in totals) < PRUNE_BATCH:
                break
        return totals

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {**self._stats, "enabled": enabled(), "backend": usage_store.selected_backend(),
                    "buffered": len(self._buffer) + (len(self._pending["rows"]) if self._pending else 0)}

    def reset(self) -> None:
        """Forget buffered rows and counters (tests and process restarts)."""
        with self._lock:
            self._wake.clear()
            self._buffer.clear()
            self._pending = None
            self._store = None
            self._next_prune = 0.0
            self._stats = {"recorded": 0, "dropped": 0, "failed_flushes": 0, "last_flush_at": None, "last_error": None}


LEDGER = UsageLedger()


def _flush_at_exit() -> None:
    if LEDGER.stats()["buffered"]:
        LEDGER.flush(timeout=_env_float("USAGE_LEDGER_SHUTDOWN_SECONDS", 5.0, 0.0, 60.0))


atexit.register(_flush_at_exit)


def hydrate_metrics(metrics_service, *, limit: Optional[int] = None) -> int:
    """Load the last day of ledger rows written before this process started into the
    dashboard's in-memory request metrics, so they survive a Container restart."""
    if not enabled():
        return 0
    limit = limit or _env_int("USAGE_METRICS_HYDRATE_ROWS", 2000, 0, 10000)
    started = datetime.fromtimestamp(metrics_service.start_time, timezone.utc)
    since = utc_timestamp(started - timedelta(hours=24))
    cutoff = utc_timestamp(started)
    records, before = [], None
    try:
        while len(records) < limit:
            size = min(usage_store.MAX_PAGE, limit - len(records))
            page = LEDGER.store().recent(since, None, before, size)
            records.extend(row for row in page if row["at"] < cutoff)
            if len(page) < size:
                break
            before = page[-1]["id"]
    except Exception as error:
        logger.warning("Recent request metrics could not be loaded from the usage ledger (%s)",
                       type(error).__name__)
        return 0
    return metrics_service.hydrate(records)


def start(metrics_service=None) -> None:
    """Start background work at application startup; never blocks startup."""
    if not enabled() or metrics_service is None:
        return
    threading.Thread(target=hydrate_metrics, args=(metrics_service,), name="usage-metrics-hydrate",
                     daemon=True).start()
