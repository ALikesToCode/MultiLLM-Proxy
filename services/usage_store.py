"""Where the usage ledger lives: D1 through the Worker's private handler, or local SQL.

On Cloudflare the Container disk is wiped whenever it sleeps, so the ledger uses the
Worker's `INTELLIGENCE_DB` through `intelligence.internal/v1/usage` (fixed statements,
no SQL crosses the boundary). Other deployments keep it in SQLite, or in PostgreSQL
when `CONTROL_PLANE_DATABASE_URL` is set. Both write the raw rows and the daily per-key,
per-model totals together, and both answer the same read operations.
"""

from __future__ import annotations

import math
import os
import re
import threading
from contextlib import closing
from typing import Any, Optional

from services import intelligence_d1_store
from services.sqlite_store import connect, storage_path

# Upper bounds in milliseconds of the latency buckets; the last bucket is open.
LATENCY_BUCKETS = (250, 500, 1000, 2000, 4000, 8000, 15000, 30000, 60000, 120000)
BUCKET_COLUMNS = tuple(f"lat_le_{bound}" for bound in LATENCY_BUCKETS) + ("lat_gt_120000",)
ROW_FIELDS = ("at", "principal", "key_prefix", "kind", "endpoint", "requested_model", "selected_model",
              "status", "latency_ms", "input_tokens", "output_tokens", "cost_usd", "cost_basis", "request_id")
EVENT_COLUMNS = ("id",) + ROW_FIELDS
TOTAL_COLUMNS = ("requests", "errors", "input_tokens", "output_tokens", "cost_usd", "priced_requests",
                 "latency_ms_total") + BUCKET_COLUMNS
GROUPS = ("day", "model", "principal")
MAX_PAGE = 500
_BATCH_ID = re.compile(r"[0-9a-f]{32}\Z")


class UsageStoreError(Exception):
    """The ledger store could not complete an operation; the cause is logged by callers."""


def latency_bucket(latency_ms: int) -> int:
    for index, bound in enumerate(LATENCY_BUCKETS):
        if latency_ms <= bound:
            return index
    return len(LATENCY_BUCKETS)


def percentile(buckets: list[int], fraction: float) -> Optional[int]:
    """Estimate a latency percentile in milliseconds from bucket counts.

    Interpolates linearly inside the bucket that holds the rank; the open last bucket
    reports its lower bound.
    """
    total = sum(buckets)
    if total <= 0:
        return None
    rank = max(1.0, fraction * total)
    seen = 0
    for index, count in enumerate(buckets):
        if count and seen + count >= rank:
            lower = LATENCY_BUCKETS[index - 1] if index else 0
            if index >= len(LATENCY_BUCKETS):
                return LATENCY_BUCKETS[-1]
            upper = LATENCY_BUCKETS[index]
            return round(lower + (upper - lower) * (rank - seen) / count)
        seen += count
    return LATENCY_BUCKETS[-1]


def summarize(row: dict) -> dict:
    """A summary row with derived error rate and latency percentiles for display."""
    buckets = [int(value or 0) for value in row.get("latency_buckets") or []]
    requests = int(row.get("requests") or 0)
    result = {key: value for key, value in row.items() if key != "latency_buckets"}
    result.update(
        cost_usd=round(float(row.get("cost_usd") or 0), 10),
        error_rate=round((int(row.get("errors") or 0) / requests * 100) if requests else 0, 1),
        latency_avg_ms=round(int(row.get("latency_ms_total") or 0) / requests) if requests else None,
        latency_p50_ms=percentile(buckets, 0.5),
        latency_p95_ms=percentile(buckets, 0.95),
    )
    return result


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _checked_rows(value: Any, fields: set[str]) -> list[dict]:
    if not isinstance(value, list) or len(value) > MAX_PAGE:
        raise UsageStoreError("invalid rows")
    for row in value:
        if not isinstance(row, dict) or set(row) != fields:
            raise UsageStoreError("invalid row")
    return value


class D1UsageStore:
    backend = "d1"

    @staticmethod
    def _call(operation: str, **values) -> dict:
        try:
            response = intelligence_d1_store.request_private_intelligence(
                {"operation": operation, **values}, endpoint="usage")
        except Exception as error:
            raise UsageStoreError(getattr(error, "code", None) or type(error).__name__) from None
        if not isinstance(response, dict):
            raise UsageStoreError("invalid response")
        return response

    def record(self, batch_id: str, rows: list[dict]) -> int:
        response = self._call("record", batch=batch_id, rows=rows)
        if set(response) != {"version", "recorded", "duplicate"} or type(response["duplicate"]) is not bool:
            raise UsageStoreError("invalid record response")
        return 0 if response["duplicate"] else len(rows)

    def totals(self, principal: str, day: str, month_start: str) -> dict:
        response = self._call("totals", principal=principal, day=day, month_start=month_start)
        totals = response.get("totals")
        if (set(response) != {"version", "totals"} or not isinstance(totals, dict)
                or set(totals) != {"day_usd", "month_usd", "day_requests", "month_requests"}
                or not all(_number(value) for value in totals.values())):
            raise UsageStoreError("invalid totals response")
        return totals

    def summary(self, group: str, since: str, until: str, principal: Optional[str], limit: int) -> list[dict]:
        response = self._call("summary", group=group, since=since, until=until, principal=principal, limit=limit)
        fields = {group, *TOTAL_COLUMNS[:7], "latency_buckets"}
        return _checked_rows(response.get("rows") if set(response) == {"version", "rows"} else None, fields)

    def recent(self, since: str, principal: Optional[str], before: Optional[int], limit: int) -> list[dict]:
        response = self._call("recent", since=since, principal=principal, before=before, limit=limit)
        return _checked_rows(response.get("rows") if set(response) == {"version", "rows"} else None, set(EVENT_COLUMNS))

    def prune(self, events_before: str, rollups_before: str, limit: int) -> dict:
        response = self._call("prune", events_before=events_before, rollups_before=rollups_before, limit=limit)
        pruned = response.get("pruned")
        if set(response) != {"version", "pruned"} or not isinstance(pruned, dict):
            raise UsageStoreError("invalid prune response")
        return pruned


class SqlUsageStore:
    """SQLite by default; PostgreSQL through the control-plane adapter when configured."""

    backend = "sql"
    _ready: set[str] = set()
    _ready_lock = threading.Lock()

    @staticmethod
    def path():
        return storage_path("USAGE_DB_PATH", "usage.sqlite3")

    def _connect(self):
        path = self.path()
        connection = connect(path)
        key = os.environ.get("CONTROL_PLANE_DATABASE_URL", "").strip() or str(path)
        with self._ready_lock:
            if key not in self._ready:
                self.ensure(connection)
                connection.commit()
                self._ready.add(key)
        return connection

    @staticmethod
    def ensure(connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                day TEXT NOT NULL,
                principal TEXT NOT NULL,
                key_prefix TEXT,
                kind TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                requested_model TEXT,
                selected_model TEXT,
                status INTEGER NOT NULL,
                latency_ms INTEGER NOT NULL,
                input_tokens INTEGER,
                output_tokens INTEGER,
                cost_usd REAL,
                cost_basis TEXT,
                request_id TEXT
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_usage_events_at ON usage_events(at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_usage_events_principal ON usage_events(principal, id)")
        buckets = ",\n".join(f"                {name} INTEGER NOT NULL DEFAULT 0" for name in BUCKET_COLUMNS)
        # Column names come only from the fixed BUCKET_COLUMNS definition.
        connection.execute(  # nosec B608  # nosemgrep
            f"""
            CREATE TABLE IF NOT EXISTS usage_daily (
                day TEXT NOT NULL,
                principal TEXT NOT NULL,
                model TEXT NOT NULL,
                requests INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                cost_usd REAL NOT NULL DEFAULT 0,
                priced_requests INTEGER NOT NULL DEFAULT 0,
                latency_ms_total INTEGER NOT NULL DEFAULT 0,
{buckets},
                PRIMARY KEY (day, principal, model)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_usage_daily_principal ON usage_daily(principal, day)")

    def record(self, batch_id: str, rows: list[dict]) -> int:
        if not _BATCH_ID.fullmatch(batch_id):
            raise UsageStoreError("invalid batch")
        groups: dict[tuple, list] = {}
        for row in rows:
            key = (row["at"][:10], row["principal"], row["selected_model"] or row["requested_model"] or "unknown")
            totals = groups.setdefault(key, [0] * len(TOTAL_COLUMNS))
            totals[0] += 1
            totals[1] += int(row["status"] >= 400)
            totals[2] += row["input_tokens"] or 0
            totals[3] += row["output_tokens"] or 0
            totals[4] += row["cost_usd"] or 0
            totals[5] += int(row["cost_usd"] is not None)
            totals[6] += row["latency_ms"]
            totals[7 + latency_bucket(row["latency_ms"])] += 1
        columns = ", ".join(TOTAL_COLUMNS)
        updates = ", ".join(f"{name} = usage_daily.{name} + excluded.{name}" for name in TOTAL_COLUMNS)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.executemany(
                    f"INSERT INTO usage_events (day, {', '.join(ROW_FIELDS)}) "  # nosec B608
                    f"VALUES ({', '.join('?' for _ in range(len(ROW_FIELDS) + 1))})",
                    [(row["at"][:10], *(row[name] for name in ROW_FIELDS)) for row in rows],
                )
                # Column names come only from the fixed TOTAL_COLUMNS definition.
                connection.executemany(
                    f"INSERT INTO usage_daily (day, principal, model, {columns}) "  # nosec B608
                    f"VALUES ({', '.join('?' for _ in range(len(TOTAL_COLUMNS) + 3))}) "
                    f"ON CONFLICT(day, principal, model) DO UPDATE SET {updates}",
                    [(*key, *totals) for key, totals in groups.items()],
                )
                connection.commit()
        except Exception as error:
            raise UsageStoreError(type(error).__name__) from None
        return len(rows)

    def _query(self, sql: str, parameters: tuple) -> list[dict]:
        try:
            with closing(self._connect()) as connection:
                return [dict(row) for row in connection.execute(sql, parameters).fetchall()]
        except Exception as error:
            raise UsageStoreError(type(error).__name__) from None

    def totals(self, principal: str, day: str, month_start: str) -> dict:
        row = self._query(
            """
            SELECT COALESCE(SUM(CASE WHEN day = ? THEN cost_usd ELSE 0 END), 0) AS day_usd,
                   COALESCE(SUM(cost_usd), 0) AS month_usd,
                   COALESCE(SUM(CASE WHEN day = ? THEN requests ELSE 0 END), 0) AS day_requests,
                   COALESCE(SUM(requests), 0) AS month_requests
            FROM usage_daily WHERE principal = ? AND day >= ? AND day <= ?
            """,
            (day, day, principal, month_start, day),
        )[0]
        return {name: float(row[name]) if name.endswith("usd") else int(row[name]) for name in row}

    def summary(self, group: str, since: str, until: str, principal: Optional[str], limit: int) -> list[dict]:
        if group not in GROUPS:
            raise UsageStoreError("invalid group")
        order = "day DESC" if group == "day" else "cost_usd DESC, requests DESC"
        sums = ", ".join(f"SUM({name}) AS {name}" for name in TOTAL_COLUMNS)
        where = "day >= ? AND day <= ?" + (" AND principal = ?" if principal is not None else "")
        parameters = (since, until) + ((principal,) if principal is not None else ()) + (limit,)
        # The group, order and column names come only from fixed definitions above.
        rows = self._query(
            f"SELECT {group}, {sums} FROM usage_daily WHERE {where} "  # nosec B608
            f"GROUP BY {group} ORDER BY {order}, {group} LIMIT ?",
            parameters,
        )
        return [{group: row[group], **{name: row[name] or 0 for name in TOTAL_COLUMNS[:7]},
                 "latency_buckets": [int(row[name] or 0) for name in BUCKET_COLUMNS]} for row in rows]

    def recent(self, since: str, principal: Optional[str], before: Optional[int], limit: int) -> list[dict]:
        where, parameters = "at >= ?", [since]
        if principal is not None:
            where += " AND principal = ?"
            parameters.append(principal)
        if before is not None:
            where += " AND id < ?"
            parameters.append(before)
        # Only fixed column names and filters are interpolated.
        return self._query(
            f"SELECT {', '.join(EVENT_COLUMNS)} FROM usage_events WHERE {where} "  # nosec B608
            "ORDER BY id DESC LIMIT ?",
            (*parameters, limit),
        )

    def prune(self, events_before: str, rollups_before: str, limit: int) -> dict:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                events = connection.execute(
                    "DELETE FROM usage_events WHERE id IN "
                    "(SELECT id FROM usage_events WHERE at < ? ORDER BY id LIMIT ?)",
                    (events_before, limit),
                ).rowcount
                rollups = connection.execute("DELETE FROM usage_daily WHERE day < ?", (rollups_before,)).rowcount
                connection.commit()
        except Exception as error:
            raise UsageStoreError(type(error).__name__) from None
        return {"events": events, "batches": 0, "rollups": rollups}


def selected_backend() -> str:
    """`USAGE_LEDGER_BACKEND` (d1 or sql), else D1 wherever the Worker provides it."""
    configured = os.environ.get("USAGE_LEDGER_BACKEND", "").strip().lower()
    if configured in {"d1", "sql"}:
        return configured
    try:
        return "d1" if intelligence_d1_store.using_d1() else "sql"
    except Exception:
        return "sql"


def open_store():
    return D1UsageStore() if selected_backend() == "d1" else SqlUsageStore()
