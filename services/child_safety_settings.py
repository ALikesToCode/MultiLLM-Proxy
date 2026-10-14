"""Durable, revision-checked administrator settings for the optional text screen."""

import logging
import threading
import time
from contextlib import closing
from dataclasses import asdict, dataclass

from services import control_state_d1
from services.intelligence_d1_store import PrivateIntelligenceError
from services.sqlite_store import connect, storage_path

logger = logging.getLogger(__name__)
CACHE_SECONDS = 5
MAX_REVISION = 2**53 - 1
SCHEMA = """CREATE TABLE IF NOT EXISTS control_child_safety_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    failure_mode TEXT NOT NULL DEFAULT 'allow' CHECK(failure_mode IN ('allow', 'block')),
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0)
)"""


class SafetyError(Exception):
    def __init__(self, code, status=503):
        super().__init__(code)
        self.code, self.status = code, status


@dataclass(frozen=True)
class SafetySettings:
    enabled: bool = False
    failure_mode: str = "allow"
    revision: int = 0

    def as_dict(self):
        return asdict(self)


def parse_settings(value):
    if (not isinstance(value, dict) or set(value) != {"enabled", "failure_mode", "revision"}
            or type(value["enabled"]) is not bool or value["failure_mode"] not in ("allow", "block")
            or type(value["revision"]) is not int or not 0 <= value["revision"] <= MAX_REVISION):
        raise SafetyError("invalid_safety_settings", 400)
    return SafetySettings(**value)


class SafetySettingsStore:
    def __init__(self, path=None):
        self.path = path or storage_path("SAFETY_DB_PATH", "safety.sqlite3")
        self._lock = threading.Lock()
        self._cached = None
        self._checked_at = 0.0

    def _connection(self):
        connection = connect(self.path)
        try:
            connection.execute(SCHEMA)
            connection.execute("INSERT INTO control_child_safety_settings (id) VALUES (1) ON CONFLICT(id) DO NOTHING")
            connection.commit()
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _local_settings(row):
        return parse_settings({"enabled": bool(row["enabled"]), "failure_mode": row["failure_mode"],
                               "revision": row["revision"]})

    def _read(self):
        if control_state_d1.using_d1():
            return parse_settings(control_state_d1.call("safety", "get")["settings"])
        with closing(self._connection()) as connection:
            return self._local_settings(connection.execute(
                "SELECT enabled, failure_mode, revision FROM control_child_safety_settings WHERE id = 1").fetchone())

    def get(self, *, fresh=False):
        with self._lock:
            now = time.monotonic()
            if not fresh and self._cached is not None and now - self._checked_at < CACHE_SECONDS:
                return self._cached
            try:
                value = self._read()
            except Exception as error:
                self._checked_at = now
                logger.warning("Child-safety settings read failed type=%s", type(error).__name__)
                if not fresh and self._cached is not None:
                    return self._cached
                # Never silently disable a persisted policy on a cold start.
                raise SafetyError("safety_settings_unavailable") from None
            self._cached, self._checked_at = value, now
            return value

    def configure(self, body):
        wanted = parse_settings(body)
        if wanted.revision == MAX_REVISION:
            raise SafetyError("invalid_safety_settings", 400)
        with self._lock:
            try:
                if control_state_d1.using_d1():
                    response = control_state_d1.call("safety", "configure", **wanted.as_dict())
                    try:
                        result = parse_settings(response["settings"])
                    except SafetyError:
                        raise SafetyError("safety_settings_unavailable") from None
                    if result != SafetySettings(wanted.enabled, wanted.failure_mode, wanted.revision + 1):
                        raise SafetyError("safety_settings_unavailable")
                else:
                    with closing(self._connection()) as connection:
                        row = connection.execute("""UPDATE control_child_safety_settings
                            SET enabled = ?, failure_mode = ?, revision = revision + 1
                            WHERE id = 1 AND revision = ? RETURNING enabled, failure_mode, revision""",
                            (int(wanted.enabled), wanted.failure_mode, wanted.revision)).fetchone()
                        if row is None:
                            raise SafetyError("safety_settings_conflict", 409)
                        connection.commit()
                        result = self._local_settings(row)
            except SafetyError:
                raise
            except PrivateIntelligenceError as error:
                if error.status == 409:
                    raise SafetyError("safety_settings_conflict", 409) from None
                raise SafetyError("safety_settings_unavailable") from None
            except Exception as error:
                logger.warning("Child-safety settings save failed type=%s", type(error).__name__)
                raise SafetyError("safety_settings_unavailable") from None
            self._cached, self._checked_at = result, time.monotonic()
            return result
