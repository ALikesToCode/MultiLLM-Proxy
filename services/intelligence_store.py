"""Durable policy and serialized allowance admission, shared across replicas."""

import json
import os
import time
import uuid
from contextlib import closing

from services.intelligence_contract import GatewayError
from services.intelligence_policy import DEFAULT_POLICY, validate_policy
from services.sqlite_store import connect, storage_path


class IntelligenceStore:
    @staticmethod
    def connect():
        if (
            os.environ.get("INTELLIGENCE_REQUIRE_DURABLE_STORAGE", "").lower() == "true"
            and not os.environ.get("CONTROL_PLANE_DATABASE_URL", "").strip()
        ):
            raise GatewayError(
                "durable_storage_required",
                "Configure external control-plane storage before enabling intelligence.",
                503,
            )
        return connect(storage_path("MODEL_REGISTRY_DB_PATH", "model_registry.sqlite3"))

    @staticmethod
    def ensure(connection):
        connection.execute("""CREATE TABLE IF NOT EXISTS intelligence_policy (
            id INTEGER PRIMARY KEY, document TEXT NOT NULL)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS intelligence_reservations (
            id TEXT PRIMARY KEY, principal TEXT NOT NULL, kind TEXT NOT NULL,
            created_at REAL NOT NULL, reserved INTEGER NOT NULL, charged INTEGER NOT NULL,
            state TEXT NOT NULL)""")
        connection.execute("""CREATE INDEX IF NOT EXISTS idx_intelligence_allowance
            ON intelligence_reservations(kind, created_at, principal)""")

    @classmethod
    def seed(cls, document):
        policy = validate_policy(document)
        with closing(cls.connect()) as connection:
            cls.ensure(connection)
            cursor = connection.execute(
                "INSERT OR IGNORE INTO intelligence_policy (id, document) VALUES (1, ?)",
                (json.dumps(policy, separators=(",", ":")),),
            )
            connection.commit()
            return bool(cursor.rowcount)

    @classmethod
    def policy(cls):
        with closing(cls.connect()) as connection:
            cls.ensure(connection)
            row = connection.execute(
                "SELECT document FROM intelligence_policy WHERE id = 1"
            ).fetchone()
            connection.commit()
        if row:
            return validate_policy(json.loads(row["document"]))
        seed = os.environ.get("INTELLIGENCE_POLICY_JSON")
        if seed:
            cls.seed(json.loads(seed))
            return cls.policy()
        return validate_policy(DEFAULT_POLICY)

    @classmethod
    def reserve(cls, principal, amount, policy, *, kind="chat", now=None):
        timestamp = time.time() if now is None else now
        cutoff = timestamp - 86400
        principal_limit, global_limit = (
            policy["principal_daily_tokens"],
            policy["global_daily_tokens"],
        )
        if kind != "chat":
            media = policy["media"][kind]
            principal_limit, global_limit = (
                media["principal_daily_requests"],
                media["daily_requests"],
            )
        with closing(cls.connect()) as connection:
            cls.ensure(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT principal, charged, state FROM intelligence_reservations
                WHERE kind = ? AND (created_at >= ? OR state != 'settled')""",
                (kind, cutoff),
            ).fetchall()
            own = sum(row["charged"] for row in rows if row["principal"] == principal)
            total = sum(row["charged"] for row in rows)
            active = sum(row["state"] == "pending" for row in rows)
            if (
                own + amount > principal_limit
                or total + amount > global_limit
                or active >= policy["max_inflight"]
            ):
                raise GatewayError(
                    "allowance_exhausted",
                    "The request exceeds the available gateway allowance.",
                    429,
                    retryable=True,
                    retry_after="60",
                )
            reservation = uuid.uuid4().hex
            connection.execute(
                """INSERT INTO intelligence_reservations
                (id, principal, kind, created_at, reserved, charged, state) VALUES (?, ?, ?, ?, ?, ?, 'pending')""",
                (reservation, principal, kind, timestamp, amount, amount),
            )
            connection.commit()
        return reservation

    @classmethod
    def settle(cls, reservation, used, complete):
        with closing(cls.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            # Unknown outcomes retain the entire reservation, including after
            # replacement or restart. They require operator reconciliation.
            if complete:
                connection.execute(
                    "UPDATE intelligence_reservations SET charged = ?, state = 'settled' WHERE id = ? AND state = 'pending'",
                    (max(0, used), reservation),
                )
            else:
                connection.execute(
                    """UPDATE intelligence_reservations
                    SET charged = CASE WHEN ? > charged THEN ? ELSE charged END, state = 'unknown'
                    WHERE id = ? AND state = 'pending'""",
                    (max(0, used), max(0, used), reservation),
                )
            connection.commit()
