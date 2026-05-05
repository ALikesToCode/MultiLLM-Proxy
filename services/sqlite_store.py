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
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        path,
        timeout=_env_int("SQLITE_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS),
    )
    connection.row_factory = sqlite3.Row
    busy_timeout_ms = max(0, _env_int("SQLITE_BUSY_TIMEOUT_MS", DEFAULT_BUSY_TIMEOUT_MS))
    connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")  # nosec B608
    connection.execute("PRAGMA foreign_keys = ON")
    if wal:
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.OperationalError as error:
            logger.warning("Unable to enable WAL mode for %s: %s", path, error)
    return connection
