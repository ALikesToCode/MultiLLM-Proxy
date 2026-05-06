import logging
import os
import secrets
import sqlite3
import string
import subprocess
import json
import shutil
import threading
import hmac
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account
from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from config import load_numbered_env_values
from error_handlers import APIError
from services.sqlite_store import connect, storage_path

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


DEFAULT_USER_SCOPES = ("chat", "models")
DEFAULT_ADMIN_SCOPES = ("admin", "chat", "metrics", "models", "users")


class AuthService:
    """Service for handling user authentication and API key management."""

    _users: Dict[str, Dict[str, Any]] = {}
    _api_key_prefix_index: Dict[str, List[str]] = {}
    _api_keys: Dict[str, str] = {}
    _google_token: Optional[str] = None
    _google_token_expiry: Optional[datetime] = None
    _google_token_lock = threading.Lock()
    _storage_lock = threading.Lock()
    _storage_path: Optional[Path] = None
    _jwt_secret: Optional[str] = os.environ.get("JWT_SECRET")

    @classmethod
    def _default_storage_path(cls) -> Path:
        return storage_path("AUTH_DB_PATH", "auth.sqlite3")

    @classmethod
    def _get_storage_path(cls) -> Path:
        if cls._storage_path is None:
            configured_path = os.environ.get("AUTH_DB_PATH")
            cls._storage_path = Path(configured_path) if configured_path else cls._default_storage_path()
        return cls._storage_path

    @classmethod
    def _connect(cls) -> sqlite3.Connection:
        return connect(cls._get_storage_path())

    @classmethod
    def _ensure_storage(cls) -> None:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                cls._ensure_users_schema(connection)
                connection.commit()

    @classmethod
    def _ensure_users_schema(cls, connection: sqlite3.Connection) -> None:
        table_exists = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'users'
            """
        ).fetchone()
        if not table_exists:
            cls._create_users_table(connection)
            cls._ensure_users_indexes(connection)
            return

        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(users)").fetchall()
        }
        if "api_key" in columns:
            cls._migrate_plaintext_users_table(connection, columns)
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }

        required_columns = {
            "api_key_prefix": "TEXT NOT NULL DEFAULT 'mllm_unknown'",
            "scopes": "TEXT NOT NULL DEFAULT 'chat,models'",
            "last_used_at": "TEXT",
            "last_used_ip": "TEXT",
            "created_by": "TEXT",
            "rotated_at": "TEXT",
            "revoked_at": "TEXT",
        }
        for column_name, column_definition in required_columns.items():
            if column_name not in columns:
                if column_name not in required_columns:
                    raise ValueError("Unsupported users column name")
                # Identifiers and definitions come from the fixed required_columns map.
                connection.execute(
                    f"ALTER TABLE users ADD COLUMN {column_name} {column_definition}"
                )

        cls._backfill_user_metadata(connection)
        cls._ensure_users_indexes(connection)

    @classmethod
    def _create_users_table(cls, connection: sqlite3.Connection, table_name: str = "users") -> None:
        if table_name not in {"users", "users_new"}:
            raise ValueError("Unsupported users table name")
        # table_name is validated against a fixed allowlist above.
        connection.execute(  # nosec B608
            f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                username TEXT PRIMARY KEY,
                api_key_hash TEXT NOT NULL,
                api_key_prefix TEXT NOT NULL,
                scopes TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT,
                last_used_at TEXT,
                last_used_ip TEXT,
                created_by TEXT,
                rotated_at TEXT,
                revoked_at TEXT
            )
            """
        )

    @classmethod
    def _ensure_users_indexes(cls, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_users_api_key_prefix
            ON users(api_key_prefix)
            """
        )

    @classmethod
    def _migrate_plaintext_users_table(
        cls,
        connection: sqlite3.Connection,
        columns: set[str],
    ) -> None:
        logger.info("Migrating users table to hash-only API key storage")
        cls._create_users_table(connection, "users_new")
        rows = connection.execute("SELECT * FROM users").fetchall()
        for row in rows:
            is_admin = bool(row["is_admin"])
            api_key = row["api_key"]
            scopes = row["scopes"] if "scopes" in row.keys() else None
            api_key_hash = (
                row["api_key_hash"]
                if "api_key_hash" in row.keys() and row["api_key_hash"]
                else cls._hash_api_key(api_key or secrets.token_urlsafe(32))
            )
            api_key_prefix = (
                row["api_key_prefix"]
                if "api_key_prefix" in row.keys() and row["api_key_prefix"]
                else cls._key_prefix(api_key)
            )
            connection.execute(
                """
                INSERT INTO users_new (
                    username, api_key_hash, api_key_prefix, scopes, is_admin,
                    created_at, last_login, last_used_at, last_used_ip,
                    created_by, rotated_at, revoked_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["username"],
                    api_key_hash,
                    api_key_prefix,
                    scopes or cls._serialize_scopes(cls._default_scopes(is_admin)),
                    int(is_admin),
                    row["created_at"],
                    row["last_login"],
                    row["last_used_at"] if "last_used_at" in row.keys() else None,
                    row["last_used_ip"] if "last_used_ip" in row.keys() else None,
                    row["created_by"] if "created_by" in row.keys() else None,
                    row["rotated_at"] if "rotated_at" in row.keys() else None,
                    row["revoked_at"] if "revoked_at" in row.keys() else None,
                ),
            )

        connection.execute("DROP TABLE users")
        connection.execute("ALTER TABLE users_new RENAME TO users")
        cls._ensure_users_indexes(connection)

    @classmethod
    def _backfill_user_metadata(cls, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT username, is_admin, api_key_prefix, scopes FROM users"
        ).fetchall()
        for row in rows:
            is_admin = bool(row["is_admin"])
            scopes = row["scopes"] or cls._serialize_scopes(cls._default_scopes(is_admin))
            prefix = row["api_key_prefix"] or "mllm_unknown"
            connection.execute(
                """
                UPDATE users
                SET api_key_prefix = ?, scopes = ?
                WHERE username = ?
                """,
                (prefix, scopes, row["username"]),
            )

    @staticmethod
    def _serialize_datetime(value: Optional[datetime]) -> Optional[str]:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    @staticmethod
    def _deserialize_datetime(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        return datetime.fromisoformat(value)

    @staticmethod
    def _default_scopes(is_admin: bool) -> tuple[str, ...]:
        return DEFAULT_ADMIN_SCOPES if is_admin else DEFAULT_USER_SCOPES

    @staticmethod
    def _serialize_scopes(scopes: Optional[List[str] | tuple[str, ...]]) -> str:
        if not scopes:
            return ",".join(DEFAULT_USER_SCOPES)
        return ",".join(sorted({scope.strip() for scope in scopes if scope and scope.strip()}))

    @staticmethod
    def _deserialize_scopes(value: Optional[str]) -> List[str]:
        if not value:
            return list(DEFAULT_USER_SCOPES)
        return [scope.strip() for scope in value.split(",") if scope.strip()]

    @staticmethod
    def _key_prefix(api_key: Optional[str]) -> str:
        if not api_key:
            return "mllm_unknown"
        return f"mllm_{api_key[:8]}"

    @staticmethod
    def _hash_api_key(api_key: str) -> str:
        return generate_password_hash(api_key)

    @classmethod
    def _row_to_user(cls, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "username": row["username"],
            "api_key_hash": row["api_key_hash"],
            "api_key_prefix": row["api_key_prefix"],
            "scopes": cls._deserialize_scopes(row["scopes"]),
            "is_admin": bool(row["is_admin"]),
            "created_at": cls._deserialize_datetime(row["created_at"]),
            "last_login": cls._deserialize_datetime(row["last_login"]),
            "last_used_at": cls._deserialize_datetime(row["last_used_at"]),
            "last_used_ip": row["last_used_ip"],
            "created_by": row["created_by"],
            "rotated_at": cls._deserialize_datetime(row["rotated_at"]),
            "revoked_at": cls._deserialize_datetime(row["revoked_at"]),
        }

    @classmethod
    def _reload_user_cache(cls) -> None:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT
                        username, api_key_hash, api_key_prefix, scopes, is_admin,
                        created_at, last_login, last_used_at, last_used_ip,
                        created_by, rotated_at, revoked_at
                    FROM users
                    ORDER BY username
                    """
                ).fetchall()
        cls._users = {
            row["username"]: cls._row_to_user(row)
            for row in rows
        }
        cls._rebuild_api_key_prefix_index()

    @classmethod
    def _load_user_by_username(cls, username: str) -> Optional[Dict[str, Any]]:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                cls._ensure_users_schema(connection)
                row = connection.execute(
                    """
                    SELECT
                        username, api_key_hash, api_key_prefix, scopes, is_admin,
                        created_at, last_login, last_used_at, last_used_ip,
                        created_by, rotated_at, revoked_at
                    FROM users
                    WHERE username = ?
                    """,
                    (username,),
                ).fetchone()
        if not row:
            cls._users.pop(username, None)
            cls._rebuild_api_key_prefix_index()
            return None

        user = cls._row_to_user(row)
        cls._users[username] = user
        cls._rebuild_api_key_prefix_index()
        return user

    @classmethod
    def _load_users_by_api_key_prefix(cls, api_key_prefix: str) -> List[tuple[str, Dict[str, Any]]]:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                cls._ensure_users_schema(connection)
                rows = connection.execute(
                    """
                    SELECT
                        username, api_key_hash, api_key_prefix, scopes, is_admin,
                        created_at, last_login, last_used_at, last_used_ip,
                        created_by, rotated_at, revoked_at
                    FROM users
                    WHERE api_key_prefix = ? AND revoked_at IS NULL
                    ORDER BY username
                    """,
                    (api_key_prefix,),
                ).fetchall()

        users = [(row["username"], cls._row_to_user(row)) for row in rows]
        for username, user in users:
            cls._users[username] = user
        if users:
            cls._rebuild_api_key_prefix_index()
        return users

    @classmethod
    def _rebuild_api_key_prefix_index(cls) -> None:
        prefix_index: Dict[str, List[str]] = {}
        for username, user in cls._users.items():
            prefix = user.get("api_key_prefix")
            if prefix:
                prefix_index.setdefault(prefix, []).append(username)
        cls._api_key_prefix_index = prefix_index

    @classmethod
    def _persist_user(
        cls,
        username: str,
        api_key_hash: str,
        api_key_prefix: str,
        scopes: Optional[List[str] | tuple[str, ...]],
        is_admin: bool,
        created_at: datetime,
        last_login: Optional[datetime] = None,
        last_used_at: Optional[datetime] = None,
        last_used_ip: Optional[str] = None,
        created_by: Optional[str] = None,
        rotated_at: Optional[datetime] = None,
        revoked_at: Optional[datetime] = None,
    ) -> None:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                cls._ensure_users_schema(connection)
                connection.execute(
                    """
                    INSERT INTO users (
                        username, api_key_hash, api_key_prefix, scopes, is_admin,
                        created_at, last_login, last_used_at, last_used_ip,
                        created_by, rotated_at, revoked_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        api_key_hash = excluded.api_key_hash,
                        api_key_prefix = excluded.api_key_prefix,
                        scopes = excluded.scopes,
                        is_admin = excluded.is_admin,
                        created_at = excluded.created_at,
                        last_login = excluded.last_login,
                        last_used_at = excluded.last_used_at,
                        last_used_ip = excluded.last_used_ip,
                        created_by = excluded.created_by,
                        rotated_at = excluded.rotated_at,
                        revoked_at = excluded.revoked_at
                    """,
                    (
                        username,
                        api_key_hash,
                        api_key_prefix,
                        cls._serialize_scopes(scopes),
                        int(is_admin),
                        cls._serialize_datetime(created_at),
                        cls._serialize_datetime(last_login),
                        cls._serialize_datetime(last_used_at),
                        last_used_ip,
                        created_by,
                        cls._serialize_datetime(rotated_at),
                        cls._serialize_datetime(revoked_at),
                    ),
                )
                connection.commit()
        cls._reload_user_cache()

    @classmethod
    def _persist_user_with_api_key(
        cls,
        username: str,
        api_key: str,
        is_admin: bool,
        created_at: datetime,
        last_login: Optional[datetime] = None,
        scopes: Optional[List[str] | tuple[str, ...]] = None,
        last_used_at: Optional[datetime] = None,
        last_used_ip: Optional[str] = None,
        created_by: Optional[str] = None,
        rotated_at: Optional[datetime] = None,
        revoked_at: Optional[datetime] = None,
    ) -> None:
        cls._persist_user(
            username=username,
            api_key_hash=cls._hash_api_key(api_key),
            api_key_prefix=cls._key_prefix(api_key),
            scopes=scopes or cls._default_scopes(is_admin),
            is_admin=is_admin,
            created_at=created_at,
            last_login=last_login,
            last_used_at=last_used_at,
            last_used_ip=last_used_ip,
            created_by=created_by,
            rotated_at=rotated_at,
            revoked_at=revoked_at,
        )

    @classmethod
    def _delete_user_record(cls, username: str) -> None:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                connection.execute("DELETE FROM users WHERE username = ?", (username,))
                connection.commit()
        cls._reload_user_cache()

    @classmethod
    def _ensure_default_admin_user(cls) -> None:
        default_username = os.environ.get("ADMIN_USERNAME", "admin")
        default_api_key = os.environ.get("ADMIN_API_KEY")
        if not default_api_key:
            logger.warning("ADMIN_API_KEY is not set; default admin user was not initialized")
            return

        existing_user = cls._users.get(default_username)
        if (
            existing_user
            and check_password_hash(existing_user["api_key_hash"], default_api_key)
            and existing_user.get("is_admin")
        ):
            return

        created_at = existing_user.get("created_at") if existing_user else _utcnow()
        last_login = existing_user.get("last_login") if existing_user else None
        cls._persist_user_with_api_key(
            username=default_username,
            api_key=default_api_key,
            is_admin=True,
            created_at=created_at,
            last_login=last_login,
            scopes=DEFAULT_ADMIN_SCOPES,
            last_used_at=existing_user.get("last_used_at") if existing_user else None,
            last_used_ip=existing_user.get("last_used_ip") if existing_user else None,
            created_by=existing_user.get("created_by") if existing_user else "system",
            rotated_at=existing_user.get("rotated_at") if existing_user else None,
            revoked_at=existing_user.get("revoked_at") if existing_user else None,
        )
        logger.info("Initialized default admin user")

    @classmethod
    def _load_provider_api_keys(cls) -> None:
        cls._api_keys = {}
        admin_key = os.environ.get("ADMIN_API_KEY")
        if admin_key:
            cls._api_keys["admin"] = admin_key

        for provider in [
            "openai",
            "cerebras",
            "xai",
            "groq",
            "azure",
            "scaleway",
            "hyperbolic",
            "sambanova",
            "openrouter",
            "opencode",
            "mimo",
            "palm",
            "together",
            "nineteen",
        ]:
            env_key = f"{provider.upper()}_API_KEY"
            api_key = os.environ.get(env_key)
            if api_key:
                cls._api_keys[provider] = api_key

        if "groq" not in cls._api_keys:
            groq_keys = load_numbered_env_values("GROQ_API_KEY")
            if groq_keys:
                cls._api_keys["groq"] = groq_keys[0]

        chutes_token = os.environ.get("CHUTES_API_TOKEN")
        if chutes_token:
            cls._api_keys["chutes"] = chutes_token

        gemini_key = os.environ.get("GEMINI_API_KEY")
        if gemini_key:
            cls._api_keys["gemini"] = gemini_key
            cls._api_keys["gemma"] = gemini_key

    @classmethod
    def _require_admin(cls) -> Dict[str, Any]:
        current_user = cls.get_current_user()
        if not current_user or not current_user.get("is_admin"):
            raise APIError("Only admin users can perform this action", status_code=403)
        return current_user

    @staticmethod
    def _generate_api_key(length: int = 32) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @classmethod
    def initialize(cls) -> None:
        """Initialize the auth service and load persisted users."""
        cls._jwt_secret = os.environ.get("JWT_SECRET")
        cls._ensure_storage()
        cls._reload_user_cache()
        cls._ensure_default_admin_user()
        cls._load_provider_api_keys()

    @classmethod
    def get_api_key(cls, provider: str) -> Optional[str]:
        """Get API key for a provider."""
        env_key = f"{provider.upper()}_API_KEY"
        api_key = os.environ.get(env_key)
        if api_key:
            return api_key
        return cls._api_keys.get(provider)

    @staticmethod
    def _build_google_service_account_credentials():
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        credentials_json = (os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON") or "").strip()
        credentials_path = (os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or "").strip()

        if credentials_json:
            credentials_info = json.loads(credentials_json)
            return service_account.Credentials.from_service_account_info(
                credentials_info,
                scopes=scopes,
            )

        if credentials_path and Path(credentials_path).is_file():
            return service_account.Credentials.from_service_account_file(
                credentials_path,
                scopes=scopes,
            )

        return None

    @classmethod
    def get_google_token(cls) -> Optional[str]:
        """Get Google Cloud access token."""
        try:
            with cls._google_token_lock:
                current_time = datetime.now()
                if (
                    cls._google_token
                    and cls._google_token_expiry
                    and current_time < cls._google_token_expiry - timedelta(minutes=5)
                ):
                    logger.debug("Using cached Google Cloud token")
                    return cls._google_token

                credentials = cls._build_google_service_account_credentials()
                if credentials is not None:
                    logger.info("Getting new Google Cloud token via service account credentials")
                    credentials.refresh(GoogleAuthRequest())
                    token = (credentials.token or "").strip()
                    expiry = credentials.expiry

                    if token:
                        cls._google_token = token
                        if expiry is not None:
                            if expiry.tzinfo is None:
                                expiry = expiry.replace(tzinfo=timezone.utc)
                            cls._google_token_expiry = expiry
                        else:
                            cls._google_token_expiry = current_time + timedelta(minutes=40)
                        logger.info("Successfully cached new Google Cloud token")
                        return token

                    logger.error("Empty token received from service account credentials")
                    cls._google_token = None
                    cls._google_token_expiry = None
                    return None

                if not shutil.which("gcloud"):
                    logger.error(
                        "No Google service account credentials configured and gcloud is not available"
                    )
                    cls._google_token = None
                    cls._google_token_expiry = None
                    return None

                logger.info("Getting new Google Cloud token via gcloud CLI fallback")
                result = subprocess.run(
                    ["gcloud", "auth", "print-access-token", "--quiet"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )

                token = result.stdout.strip()
                if token:
                    cls._google_token = token
                    cls._google_token_expiry = current_time + timedelta(minutes=40)
                    logger.info("Successfully cached new Google Cloud token for 40 minutes")
                    return token

                logger.error("Empty token received from gcloud command")
                cls._google_token = None
                cls._google_token_expiry = None
                return None

        except subprocess.CalledProcessError as error:
            error_output = error.stderr.decode("utf-8") if isinstance(error.stderr, bytes) else str(error.stderr)
            logger.error("Error getting Google token: %s", error_output)
        except subprocess.TimeoutExpired:
            logger.error("Timeout while getting Google token")
        except Exception as error:
            logger.error("Unexpected error getting Google token: %s", error)

        cls._google_token = None
        cls._google_token_expiry = None
        return None

    @classmethod
    def is_authenticated(cls) -> bool:
        """Check if the current user is authenticated."""
        return bool(session.get("authenticated") and session.get("user"))

    @classmethod
    def get_current_user(cls) -> Optional[Dict[str, Any]]:
        """Get the current authenticated user."""
        if not cls.is_authenticated():
            return None
        return session.get("user")

    @classmethod
    def _public_user(cls, username: str, user: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": username,
            "username": username,
            "api_key_prefix": user["api_key_prefix"],
            "scopes": list(user.get("scopes") or []),
            "is_admin": user["is_admin"],
            "created_at": cls._serialize_datetime(user["created_at"]),
            "last_login": cls._serialize_datetime(user["last_login"]),
            "last_used_at": cls._serialize_datetime(user["last_used_at"]),
            "last_used_ip": user.get("last_used_ip"),
            "created_by": user.get("created_by"),
            "rotated_at": cls._serialize_datetime(user["rotated_at"]),
            "revoked_at": cls._serialize_datetime(user["revoked_at"]),
        }

    @classmethod
    def _update_login(cls, username: str, last_login: datetime) -> None:
        user = cls._users[username]
        cls._persist_user(
            username=username,
            api_key_hash=user["api_key_hash"],
            api_key_prefix=user["api_key_prefix"],
            scopes=user["scopes"],
            is_admin=user.get("is_admin", False),
            created_at=user["created_at"] or last_login,
            last_login=last_login,
            last_used_at=user.get("last_used_at"),
            last_used_ip=user.get("last_used_ip"),
            created_by=user.get("created_by"),
            rotated_at=user.get("rotated_at"),
            revoked_at=user.get("revoked_at"),
        )

    @classmethod
    def _update_key_usage(cls, username: str, remote_addr: Optional[str] = None) -> None:
        user = cls._users.get(username)
        if not user:
            return
        last_used_at = _utcnow()
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                try:
                    connection.execute(
                        """
                        UPDATE users
                        SET last_used_at = ?, last_used_ip = ?
                        WHERE username = ?
                        """,
                        (cls._serialize_datetime(last_used_at), remote_addr, username),
                    )
                    connection.commit()
                except sqlite3.OperationalError as exc:
                    if "no such table: users" not in str(exc):
                        raise
                    logger.warning(
                        "Skipping API key usage persistence because auth storage is not initialized",
                        extra={"username": username},
                    )
        user["last_used_at"] = last_used_at
        user["last_used_ip"] = remote_addr

    @classmethod
    def verify_api_key(cls, api_key: Optional[str], remote_addr: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Verify a bearer API key without storing or comparing plaintext user keys."""
        if not api_key:
            return None

        default_username = os.environ.get("ADMIN_USERNAME", "admin")
        admin_api_key = os.environ.get("ADMIN_API_KEY")
        if admin_api_key and hmac.compare_digest(api_key, admin_api_key):
            user = cls._users.get(default_username)
            if user:
                cls._update_key_usage(default_username, remote_addr)
                return cls._public_user(default_username, cls._users[default_username])
            logger.error(
                "Default admin API key matched but persistent admin user is missing",
                extra={"username": default_username},
            )
            return None

        for username, user in cls._load_users_by_api_key_prefix(cls._key_prefix(api_key)):
            if check_password_hash(user["api_key_hash"], api_key):
                cls._update_key_usage(username, remote_addr)
                return cls._public_user(username, cls._users[username])

        return None

    @classmethod
    def authenticate_user(cls, username: str, api_key: str) -> bool:
        """Authenticate a user with username and API key."""
        user = cls._load_user_by_username(username)
        if not user:
            return False

        if not check_password_hash(user["api_key_hash"], api_key):
            return False

        last_login = _utcnow()
        cls._update_login(username, last_login)
        user = cls._users[username]

        session["user"] = {
            "username": username,
            "is_admin": user.get("is_admin", False),
            "api_key_prefix": user.get("api_key_prefix"),
            "scopes": list(user.get("scopes") or []),
            "session_id": secrets.token_urlsafe(16),
        }
        session["authenticated"] = True
        return True

    @classmethod
    def logout(cls) -> None:
        """Log out the current user."""
        session.pop("user", None)
        session.pop("authenticated", None)

    @classmethod
    def list_users(cls) -> List[Dict[str, Any]]:
        """List all users (admin only)."""
        cls._require_admin()
        cls._reload_user_cache()
        return [cls._public_user(username, user) for username, user in sorted(cls._users.items())]

    @classmethod
    def count_users(cls) -> int:
        """Return the total number of persisted users."""
        cls._reload_user_cache()
        return len(cls._users)

    @classmethod
    def create_user(cls, username: str, is_admin: bool = False) -> Dict[str, Any]:
        """Create a new user and persist it."""
        cls._require_admin()
        if not username:
            raise APIError("Username is required", status_code=400)
        if username in cls._users:
            raise APIError("User already exists", status_code=409)

        api_key = cls._generate_api_key()
        created_at = _utcnow()
        scopes = cls._default_scopes(is_admin)
        current_user = cls.get_current_user() or {}
        cls._persist_user_with_api_key(
            username=username,
            api_key=api_key,
            is_admin=is_admin,
            created_at=created_at,
            last_login=None,
            scopes=scopes,
            created_by=current_user.get("username"),
        )

        return {
            "id": username,
            "username": username,
            "api_key": api_key,
            "api_key_prefix": cls._key_prefix(api_key),
            "scopes": list(scopes),
            "is_admin": is_admin,
            "created_at": cls._serialize_datetime(created_at),
            "last_login": None,
        }

    @classmethod
    def delete_user(cls, username: str) -> None:
        """Delete an existing user."""
        current_user = cls._require_admin()
        cls._load_user_by_username(username)
        if username not in cls._users:
            raise APIError("User not found", status_code=404)
        if username == current_user.get("username"):
            raise APIError("You cannot delete the currently authenticated admin user", status_code=400)
        cls._delete_user_record(username)

    @classmethod
    def rotate_api_key(cls, username: str) -> Dict[str, Any]:
        """Rotate a user's API key."""
        cls._require_admin()
        cls._load_user_by_username(username)
        user = cls._users.get(username)
        if not user:
            raise APIError("User not found", status_code=404)

        new_api_key = cls._generate_api_key()
        rotated_at = _utcnow()
        cls._persist_user_with_api_key(
            username=username,
            api_key=new_api_key,
            is_admin=user["is_admin"],
            created_at=user["created_at"] or _utcnow(),
            last_login=user["last_login"],
            scopes=user["scopes"],
            last_used_at=user.get("last_used_at"),
            last_used_ip=user.get("last_used_ip"),
            created_by=user.get("created_by"),
            rotated_at=rotated_at,
            revoked_at=user.get("revoked_at"),
        )

        return {
            "id": username,
            "username": username,
            "api_key": new_api_key,
            "api_key_prefix": cls._key_prefix(new_api_key),
            "rotated_at": cls._serialize_datetime(rotated_at),
        }
