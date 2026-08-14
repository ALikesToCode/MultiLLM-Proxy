import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping

from providers.registry import get_registry
from services.model_registry import ModelRegistry
from services.sqlite_store import connect, storage_path


AUTO_ROUTE_PREFIX = "auto:"
MAX_AUTO_ROUTE_CANDIDATES = 16
DEFAULT_AUTO_ROUTES = {
    "auto:glm-5.2": (
        "nanogpt:glm-5.2",
        "opencode:glm-5.2",
        "navyai:glm-5.2",
    ),
}
_ROUTE_ID_PATTERN = re.compile(r"^auto:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AutoRoute:
    id: str
    candidates: tuple[str, ...]
    updated_at: str


class AutoRouteService:
    """Persist ordered, explicit provider candidates for virtual chat models."""

    @staticmethod
    def _connect() -> sqlite3.Connection:
        return connect(storage_path("MODEL_REGISTRY_DB_PATH", "model_registry.sqlite3"))

    @classmethod
    def _ensure_storage(cls, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auto_routes (
                route_id TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auto_route_candidates (
                route_id TEXT NOT NULL,
                priority INTEGER NOT NULL,
                model_id TEXT NOT NULL,
                PRIMARY KEY (route_id, priority),
                UNIQUE (route_id, model_id),
                FOREIGN KEY (route_id) REFERENCES auto_routes(route_id)
                    ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auto_route_candidates_route_priority
            ON auto_route_candidates(route_id, priority)
            """
        )

        for route_id, candidates in DEFAULT_AUTO_ROUTES.items():
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO auto_routes (route_id, updated_at)
                VALUES (?, ?)
                """,
                (route_id, _utcnow_iso()),
            )
            if cursor.rowcount:
                connection.executemany(
                    """
                    INSERT INTO auto_route_candidates (route_id, priority, model_id)
                    VALUES (?, ?, ?)
                    """,
                    [
                        (route_id, priority, model_id)
                        for priority, model_id in enumerate(candidates)
                    ],
                )

    @staticmethod
    def is_auto_route(model_id: object) -> bool:
        return isinstance(model_id, str) and model_id.lower().startswith(
            AUTO_ROUTE_PREFIX
        )

    @staticmethod
    def normalize_route_id(route_id: object) -> str:
        if not isinstance(route_id, str):
            raise ValueError("Auto route ID must be a string")
        normalized = route_id.strip()
        if not _ROUTE_ID_PATTERN.fullmatch(normalized):
            raise ValueError(
                "Auto route ID must use auto:<name> with letters, numbers, dots, "
                "underscores, or hyphens"
            )
        return normalized

    @classmethod
    def normalize_candidates(
        cls,
        candidates: object,
        base_urls: Mapping[str, str],
    ) -> tuple[str, ...]:
        if not isinstance(candidates, list):
            raise ValueError("Auto route candidates must be a JSON array")
        if not candidates:
            raise ValueError("Auto route requires at least one candidate")
        if len(candidates) > MAX_AUTO_ROUTE_CANDIDATES:
            raise ValueError(
                f"Auto route supports at most {MAX_AUTO_ROUTE_CANDIDATES} candidates"
            )

        supported_providers = set(get_registry(base_urls))
        normalized: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            if not isinstance(candidate, str) or len(candidate) > 256:
                raise ValueError("Each auto route candidate must be a model ID string")
            candidate_id = candidate.strip()
            if not _MODEL_ID_PATTERN.fullmatch(candidate_id):
                raise ValueError(
                    "Auto route model IDs may contain letters, numbers, dots, "
                    "underscores, slashes, colons, plus signs, at signs, or hyphens"
                )
            provider, provider_model = ModelRegistry.parse_model_id(candidate_id)
            if provider == "auto":
                raise ValueError("Auto routes cannot contain another auto route")
            if provider not in supported_providers:
                raise ValueError(f"Unsupported provider in auto route: {provider}")
            model_id = f"{provider}:{provider_model}"
            if model_id in seen:
                raise ValueError(f"Duplicate auto route candidate: {model_id}")
            seen.add(model_id)
            normalized.append(model_id)
        return tuple(normalized)

    @classmethod
    def _rows_to_routes(cls, rows: Iterable[sqlite3.Row]) -> list[AutoRoute]:
        candidates_by_route: dict[str, list[str]] = {}
        updated_at_by_route: dict[str, str] = {}
        for row in rows:
            route_id = str(row["route_id"])
            updated_at_by_route[route_id] = str(row["updated_at"])
            candidates = candidates_by_route.setdefault(route_id, [])
            if row["model_id"] is not None:
                candidates.append(str(row["model_id"]))
        return [
            AutoRoute(
                id=route_id,
                candidates=tuple(candidates),
                updated_at=updated_at_by_route[route_id],
            )
            for route_id, candidates in candidates_by_route.items()
        ]

    @classmethod
    def list_routes(cls) -> list[AutoRoute]:
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            rows = connection.execute(
                """
                SELECT routes.route_id, routes.updated_at, candidates.model_id
                FROM auto_routes AS routes
                LEFT JOIN auto_route_candidates AS candidates
                    ON candidates.route_id = routes.route_id
                ORDER BY routes.route_id, candidates.priority
                """
            ).fetchall()
        return cls._rows_to_routes(rows)

    @classmethod
    def get_route(cls, route_id: object) -> AutoRoute | None:
        normalized = cls.normalize_route_id(route_id)
        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            rows = connection.execute(
                """
                SELECT routes.route_id, routes.updated_at, candidates.model_id
                FROM auto_routes AS routes
                LEFT JOIN auto_route_candidates AS candidates
                    ON candidates.route_id = routes.route_id
                WHERE routes.route_id = ?
                ORDER BY candidates.priority
                """,
                (normalized,),
            ).fetchall()
        routes = cls._rows_to_routes(rows)
        return routes[0] if routes else None

    @classmethod
    def save_route(
        cls,
        route_id: object,
        candidates: object,
        base_urls: Mapping[str, str],
    ) -> AutoRoute:
        normalized_route_id = cls.normalize_route_id(route_id)
        normalized_candidates = cls.normalize_candidates(candidates, base_urls)
        updated_at = _utcnow_iso()

        with closing(cls._connect()) as connection:
            cls._ensure_storage(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO auto_routes (route_id, updated_at)
                VALUES (?, ?)
                ON CONFLICT(route_id) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (normalized_route_id, updated_at),
            )
            connection.execute(
                "DELETE FROM auto_route_candidates WHERE route_id = ?",
                (normalized_route_id,),
            )
            connection.executemany(
                """
                INSERT INTO auto_route_candidates (route_id, priority, model_id)
                VALUES (?, ?, ?)
                """,
                [
                    (normalized_route_id, priority, model_id)
                    for priority, model_id in enumerate(normalized_candidates)
                ],
            )
            connection.commit()

        return AutoRoute(
            id=normalized_route_id,
            candidates=normalized_candidates,
            updated_at=updated_at,
        )
