import logging
import os
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_BUSY_TIMEOUT_MS = 10_000
DEFAULT_TIMEOUT_SECONDS = 10


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        logger.warning("Invalid integer for %s; using default %s", name, default)
        return default


def storage_path(env_name: str, default_filename: str) -> Path:
    configured_path = os.environ.get(env_name)
    if configured_path:
        return Path(configured_path)
    return Path(__file__).resolve().parent.parent / "instance" / default_filename


def connect(path: Path, *, wal: bool = True) -> sqlite3.Connection:
    database_url = os.environ.get("CONTROL_PLANE_DATABASE_URL", "").strip()
    if database_url:
        from services.postgres_store import PostgresConnection

        return PostgresConnection(database_url)  # type: ignore[return-value]
    parent_existed = path.parent.exists()
    database_existed = path.exists()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not parent_existed:
        path.parent.chmod(0o700)
    connection = sqlite3.connect(
        path,
        timeout=_env_int("SQLITE_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS),
    )
    if not database_existed:
        path.chmod(0o600)
    connection.row_factory = sqlite3.Row
    # The interpolated value has already been parsed as an integer above.
    busy_timeout_ms = max(0, _env_int("SQLITE_BUSY_TIMEOUT_MS", DEFAULT_BUSY_TIMEOUT_MS))
    connection.execute(  # nosec B608  # nosemgrep
        f"PRAGMA busy_timeout = {busy_timeout_ms}"
    )
    connection.execute("PRAGMA foreign_keys = ON")
    if wal:
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.OperationalError as error:
            logger.warning(
                "Unable to enable WAL mode type=%s",
                type(error).__name__,
            )
    return connection
