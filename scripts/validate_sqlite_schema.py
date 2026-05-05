#!/usr/bin/env python3
import argparse
import os
import sys
import tempfile
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _index_names(connection, table_name: str) -> set[str]:
    return {
        row["name"]
        for row in connection.execute(f"PRAGMA index_list({table_name})").fetchall()  # nosec B608
    }


def _require_indexes(connection, table_name: str, expected_indexes: set[str]) -> None:
    missing = expected_indexes - _index_names(connection, table_name)
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise RuntimeError(f"{table_name} is missing index(es): {missing_list}")


def _prepare_temp_env() -> tempfile.TemporaryDirectory:
    tempdir = tempfile.TemporaryDirectory()
    os.environ["AUTH_DB_PATH"] = str(Path(tempdir.name) / "auth.sqlite3")
    os.environ["RATE_LIMIT_DB_PATH"] = str(Path(tempdir.name) / "rate_limits.sqlite3")
    os.environ["MODEL_REGISTRY_DB_PATH"] = str(Path(tempdir.name) / "model_registry.sqlite3")
    return tempdir


def validate_schema() -> None:
    from services.auth_service import AuthService
    from services.model_registry import ModelRegistry
    from services.rate_limit_service import RateLimitService

    AuthService._storage_path = None
    RateLimitService._storage_path = None
    ModelRegistry._storage_path = None

    AuthService._ensure_storage()
    with closing(AuthService._connect()) as connection:
        _require_indexes(connection, "users", {"idx_users_api_key_prefix"})

    with closing(RateLimitService._connect()) as connection:
        RateLimitService._ensure_storage(connection)
        connection.commit()
        _require_indexes(
            connection,
            "request_usage",
            {"idx_request_usage_window", "idx_request_usage_created_at"},
        )

    with closing(ModelRegistry._connect()) as connection:
        ModelRegistry._ensure_storage(connection)
        connection.commit()
        row = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'model_overrides'
            """
        ).fetchone()
        if not row:
            raise RuntimeError("model_overrides table was not created")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate inline SQLite schema migrations.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply schema creation/migrations to the configured SQLite paths.",
    )
    args = parser.parse_args()

    tempdir = None
    if not args.apply:
        tempdir = _prepare_temp_env()

    try:
        validate_schema()
    finally:
        if tempdir is not None:
            tempdir.cleanup()

    target = "configured database files" if args.apply else "temporary database files"
    print(f"SQLite schema validation passed for {target}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
