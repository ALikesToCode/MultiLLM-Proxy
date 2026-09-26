import logging
import os
import secrets
import sqlite3
import string
import subprocess
import json
import shutil
import threading
import hashlib
import hmac
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import session
from werkzeug.security import check_password_hash

from config import load_numbered_env_values
from error_handlers import APIError
from providers.image_relays import image_relay_api_key, image_relay_specs
from services.auth_primitives import (
    DEFAULT_ADMIN_SCOPES,
    DEFAULT_USER_SCOPES,
    MAX_API_KEY_LENGTH,
    MAX_USERNAME_LENGTH,
    build_api_key_prefix,
    default_scopes,
    deserialize_datetime,
    deserialize_scopes,
    hash_api_key,
    normalized_username,
    provider_api_key_env_names,
    provider_credential_env_names,
    require_valid_username,
    serialize_datetime,
    serialize_scopes,
    usable_credential,
)
from services import key_controls
from services.nanogpt_key_pool import configured_nanogpt_keys
from services import user_store
from services.sqlite_store import connect, storage_path
from services.intelligence_auth import (
    KEY_NAMESPACE, reject_local_integration_management, verify_integration_key,
)
from services.user_provisioning import create_user as provision_user
from services.dashboard_sso import restrict_session_user

logger = logging.getLogger(__name__)


USAGE_WRITE_INTERVAL_SECONDS = 60
# A verified dashboard key skips storage and scrypt for this long. Every account change in
# this process clears the memo; a change made elsewhere applies within this window.
VERIFIED_KEY_SECONDS = 60
MAX_VERIFIED_KEYS = 1024


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthService:
    """Service for handling user authentication and API key management."""

    _users: Dict[str, Dict[str, Any]] = {}
    _api_key_prefix_index: Dict[str, List[str]] = {}
    _api_keys: Dict[str, str] = {}
    _google_token: Optional[str] = None
    _google_token_expiry: Optional[datetime] = None
    _google_token_lock = threading.Lock()
    _storage_lock = threading.Lock()
    _verified_keys: Dict[str, tuple[float, str]] = {}
    _verified_lock = threading.Lock()
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
        if user_store.using_d1():
            # The Worker's D1 migrations own the control_users schema.
            return
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
            # Per-key controls; DOUBLE PRECISION keeps PostgreSQL budgets exact enough.
            "daily_budget_usd": "DOUBLE PRECISION",
            "monthly_budget_usd": "DOUBLE PRECISION",
            "allowed_models": "TEXT",
            "allowed_ips": "TEXT",
            "expires_at": "TEXT",
        }
        for column_name, column_definition in required_columns.items():
            if column_name not in columns:
                if column_name not in required_columns:
                    raise ValueError("Unsupported users column name")
                # Identifiers and definitions come from the fixed required_columns map.
                connection.execute(  # nosemgrep
                    f"ALTER TABLE users ADD COLUMN {column_name} {column_definition}"
                )

        cls._backfill_user_metadata(connection)
        cls._ensure_users_indexes(connection)

    @classmethod
    def _create_users_table(cls, connection: sqlite3.Connection, table_name: str = "users") -> None:
        if table_name not in {"users", "users_new"}:
            raise ValueError("Unsupported users table name")
        # table_name is validated against a fixed allowlist above.
        connection.execute(  # nosec B608  # nosemgrep
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
                revoked_at TEXT,
                daily_budget_usd DOUBLE PRECISION,
                monthly_budget_usd DOUBLE PRECISION,
                allowed_models TEXT,
                allowed_ips TEXT,
                expires_at TEXT
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
                else hash_api_key(api_key or secrets.token_urlsafe(32))
            )
            api_key_prefix = (
                row["api_key_prefix"]
                if "api_key_prefix" in row.keys() and row["api_key_prefix"]
                else build_api_key_prefix(api_key)
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
                    scopes or serialize_scopes(default_scopes(is_admin)),
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
            scopes = row["scopes"] or serialize_scopes(default_scopes(is_admin))
            prefix = row["api_key_prefix"] or "mllm_unknown"
            connection.execute(
                """
                UPDATE users
                SET api_key_prefix = ?, scopes = ?
                WHERE username = ?
                """,
                (prefix, scopes, row["username"]),
            )

    @classmethod
    def _row_to_user(cls, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "username": row["username"],
            "api_key_hash": row["api_key_hash"],
            "api_key_prefix": row["api_key_prefix"],
            "scopes": deserialize_scopes(row["scopes"]),
            "is_admin": bool(row["is_admin"]),
            "created_at": deserialize_datetime(row["created_at"]),
            "last_login": deserialize_datetime(row["last_login"]),
            "last_used_at": deserialize_datetime(row["last_used_at"]),
            "last_used_ip": row["last_used_ip"],
            "created_by": row["created_by"],
            "rotated_at": deserialize_datetime(row["rotated_at"]),
            "revoked_at": deserialize_datetime(row["revoked_at"]),
            **key_controls.from_storage(
                {name: key_controls.row_value(row, name) for name in key_controls.CONTROL_FIELDS}
            ),
        }

    @classmethod
    def _reload_user_cache(cls) -> None:
        if user_store.using_d1():
            rows = user_store.list_users()
        else:
            with cls._storage_lock:
                with closing(cls._connect()) as connection:
                    rows = connection.execute(
                        """
                        SELECT
                            username, api_key_hash, api_key_prefix, scopes, is_admin,
                            created_at, last_login, last_used_at, last_used_ip,
                            created_by, rotated_at, revoked_at, daily_budget_usd,
                            monthly_budget_usd, allowed_models, allowed_ips, expires_at
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
        if user_store.using_d1():
            row = user_store.get_user(username)
        else:
            with cls._storage_lock:
                with closing(cls._connect()) as connection:
                    cls._ensure_users_schema(connection)
                    row = connection.execute(
                        """
                        SELECT
                            username, api_key_hash, api_key_prefix, scopes, is_admin,
                            created_at, last_login, last_used_at, last_used_ip,
                            created_by, rotated_at, revoked_at, daily_budget_usd,
                            monthly_budget_usd, allowed_models, allowed_ips, expires_at
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
        if user_store.using_d1():
            rows = user_store.users_by_prefix(api_key_prefix)
        else:
            with cls._storage_lock:
                with closing(cls._connect()) as connection:
                    cls._ensure_users_schema(connection)
                    rows = connection.execute(
                        """
                        SELECT
                            username, api_key_hash, api_key_prefix, scopes, is_admin,
                            created_at, last_login, last_used_at, last_used_ip,
                            created_by, rotated_at, revoked_at, daily_budget_usd,
                            monthly_budget_usd, allowed_models, allowed_ips, expires_at
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
        controls: Optional[Dict[str, Any]] = None,
    ) -> None:
        cls._forget_verified_keys()
        stored_controls = {**key_controls.empty(), **(controls or {})}
        if user_store.using_d1():
            user_store.upsert_user({
                "username": username,
                "api_key_hash": api_key_hash,
                "api_key_prefix": api_key_prefix,
                "scopes": serialize_scopes(scopes),
                "is_admin": int(is_admin),
                "created_at": serialize_datetime(created_at),
                "last_login": serialize_datetime(last_login),
                "last_used_at": serialize_datetime(last_used_at),
                "last_used_ip": last_used_ip,
                "created_by": created_by,
                "rotated_at": serialize_datetime(rotated_at),
                "revoked_at": serialize_datetime(revoked_at),
                **{name: stored_controls[name] for name in key_controls.CONTROL_FIELDS},
            })
            cls._reload_user_cache()
            return
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                cls._ensure_users_schema(connection)
                connection.execute(
                    """
                    INSERT INTO users (
                        username, api_key_hash, api_key_prefix, scopes, is_admin,
                        created_at, last_login, last_used_at, last_used_ip,
                        created_by, rotated_at, revoked_at, daily_budget_usd,
                        monthly_budget_usd, allowed_models, allowed_ips, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        revoked_at = excluded.revoked_at,
                        daily_budget_usd = excluded.daily_budget_usd,
                        monthly_budget_usd = excluded.monthly_budget_usd,
                        allowed_models = excluded.allowed_models,
                        allowed_ips = excluded.allowed_ips,
                        expires_at = excluded.expires_at
                    """,
                    (
                        username,
                        api_key_hash,
                        api_key_prefix,
                        serialize_scopes(scopes),
                        int(is_admin),
                        serialize_datetime(created_at),
                        serialize_datetime(last_login),
                        serialize_datetime(last_used_at),
                        last_used_ip,
                        created_by,
                        serialize_datetime(rotated_at),
                        serialize_datetime(revoked_at),
                        *(stored_controls[name] for name in key_controls.CONTROL_FIELDS),
                    ),
                )
                connection.commit()
        cls._reload_user_cache()

    @staticmethod
    def _key_digest(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    @classmethod
    def _remembered_username(cls, api_key: str) -> Optional[str]:
        digest = cls._key_digest(api_key)
        with cls._verified_lock:
            entry = cls._verified_keys.get(digest)
            if entry and entry[0] > time.monotonic():
                return entry[1]
            cls._verified_keys.pop(digest, None)
        return None

    @classmethod
    def _remember_key(cls, api_key: str, username: str) -> None:
        with cls._verified_lock:
            if len(cls._verified_keys) >= MAX_VERIFIED_KEYS:
                cls._verified_keys.pop(next(iter(cls._verified_keys)))
            cls._verified_keys[cls._key_digest(api_key)] = (time.monotonic() + VERIFIED_KEY_SECONDS, username)

    @classmethod
    def _forget_verified_keys(cls) -> None:
        with cls._verified_lock:
            cls._verified_keys.clear()

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
        controls: Optional[Dict[str, Any]] = None,
    ) -> None:
        cls._persist_user(
            username=username,
            api_key_hash=hash_api_key(api_key),
            api_key_prefix=build_api_key_prefix(api_key),
            scopes=scopes or default_scopes(is_admin),
            is_admin=is_admin,
            created_at=created_at,
            last_login=last_login,
            last_used_at=last_used_at,
            last_used_ip=last_used_ip,
            created_by=created_by,
            rotated_at=rotated_at,
            revoked_at=revoked_at,
            controls=controls,
        )

    @classmethod
    def _delete_user_record(cls, username: str) -> None:
        cls._forget_verified_keys()
        if user_store.using_d1():
            user_store.delete_user(username)
        else:
            with cls._storage_lock:
                with closing(cls._connect()) as connection:
                    connection.execute("DELETE FROM users WHERE username = ?", (username,))
                    connection.commit()
        cls._reload_user_cache()

    @classmethod
    def _ensure_default_admin_user(cls) -> None:
        default_username = normalized_username(
            os.environ.get("ADMIN_USERNAME", "admin")
        )
        if default_username is None:
            raise RuntimeError(
                f"ADMIN_USERNAME must be 1 to {MAX_USERNAME_LENGTH} characters "
                "and contain no control characters"
            )
        default_api_key = os.environ.get("ADMIN_API_KEY")
        if not default_api_key:
            logger.warning("ADMIN_API_KEY is not set; default admin user was not initialized")
            return

        existing_user = cls._users.get(default_username)
        if (
            existing_user
            and check_password_hash(existing_user["api_key_hash"], default_api_key)
            and existing_user.get("is_admin")
            and not existing_user.get("revoked_at")
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
            revoked_at=None,
            controls=cls._stored_controls(existing_user) if existing_user else None,
        )
        logger.info("Initialized default admin user")

    @classmethod
    def _load_provider_api_keys(cls) -> None:
        cls._api_keys = {}
        admin_key = os.environ.get("ADMIN_API_KEY")
        if admin_key:
            cls._api_keys["admin"] = admin_key

        providers = [
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
            "nanogpt",
            "navyai",
            "linkapi",
            "codex-easy",
            "kimi-code",
            "palm",
            "together",
            "nineteen",
        ]
        providers.extend(spec.provider for spec in image_relay_specs())
        for provider in dict.fromkeys(providers):
            api_key = next(
                (
                    os.environ[env_key]
                    for env_key in provider_api_key_env_names(provider)
                    if os.environ.get(env_key)
                ),
                None,
            )
            if not api_key:
                api_key = image_relay_api_key(provider)
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
        cls._forget_verified_keys()
        cls._ensure_storage()
        try:
            cls._reload_user_cache()
            cls._ensure_default_admin_user()
        except APIError:
            if not user_store.using_d1():
                raise
            # Serve without a boot-time copy; reads go to D1 per request, and the
            # environment-managed admin is written on its first authenticated use.
            logger.warning("Account storage was unavailable at startup")
        cls._load_provider_api_keys()

    @classmethod
    def get_api_key(cls, provider: str) -> Optional[str]:
        """Get API key for a provider."""
        for env_key in provider_api_key_env_names(provider):
            api_key = usable_credential(os.environ.get(env_key), env_key)
            if api_key:
                return api_key
        relay_key = usable_credential(image_relay_api_key(provider), "IMAGE_RELAY_API_KEYS_JSON")
        if relay_key:
            return relay_key
        return usable_credential(cls._api_keys.get(provider))

    @classmethod
    def provider_credential_env_names(cls, provider: str) -> tuple[str, ...]:
        """Return safe environment-variable names for dashboard setup guidance."""
        return provider_credential_env_names(provider)

    @classmethod
    def get_api_keys(cls, provider: str) -> List[str]:
        """Get every configured key for providers that support a key pool."""
        if provider == "nanogpt":
            return configured_nanogpt_keys()
        api_key = cls.get_api_key(provider)
        return [api_key] if api_key else []

    @staticmethod
    def _build_google_service_account_credentials():
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        credentials_json = (os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON") or "").strip()
        credentials_path = (os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or "").strip()

        if credentials_json:
            # Keep optional Google modules off the default container cold start.
            from google.oauth2 import service_account  # noqa: PLC0415

            credentials_info = json.loads(credentials_json)
            return service_account.Credentials.from_service_account_info(
                credentials_info,
                scopes=scopes,
            )

        if credentials_path and Path(credentials_path).is_file():
            # Keep optional Google modules off the default container cold start.
            from google.oauth2 import service_account  # noqa: PLC0415

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
                    # Import transport only when service-account refresh is used.
                    from google.auth.transport import requests as google_auth_requests  # noqa: E501, PLC0415

                    logger.info("Getting new Google Cloud token via service account credentials")
                    credentials.refresh(google_auth_requests.Request())
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

                gcloud_path = shutil.which("gcloud")
                if not gcloud_path:
                    logger.error(
                        "No Google service account credentials configured and gcloud is not available"
                    )
                    cls._google_token = None
                    cls._google_token_expiry = None
                    return None

                logger.info("Getting new Google Cloud token via gcloud CLI fallback")
                result = subprocess.run(
                    [gcloud_path, "auth", "print-access-token", "--quiet"],
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
            logger.error(
                "gcloud command failed return_code=%s",
                error.returncode,
            )
        except subprocess.TimeoutExpired:
            logger.error("Timeout while getting Google token")
        except Exception as error:
            logger.error(
                "Unexpected gcloud error type=%s",
                type(error).__name__,
            )

        cls._google_token = None
        cls._google_token_expiry = None
        return None

    @classmethod
    def is_authenticated(cls) -> bool:
        """Check if the current user is authenticated."""
        return cls.get_current_user() is not None

    @classmethod
    def get_current_user(cls) -> Optional[Dict[str, Any]]:
        """Revalidate the signed session against the persisted user record."""
        session_user = session.get("user")
        if session.get("authenticated") is not True or not isinstance(
            session_user,
            dict,
        ):
            return None

        username = session_user.get("username")
        session_prefix = session_user.get("api_key_prefix")
        if not isinstance(username, str) or not isinstance(session_prefix, str):
            session.clear()
            return None

        try:
            user = cls._load_user_by_username(username)
        except Exception as error:
            logger.error(
                "Could not revalidate authenticated session (%s)",
                type(error).__name__,
            )
            session.clear()
            return None

        if (
            not user
            or user.get("revoked_at")
            or key_controls.expired(user)
            or not hmac.compare_digest(
                session_prefix,
                str(user.get("api_key_prefix") or ""),
            )
        ):
            session.clear()
            return None

        current_user = {
            "username": username,
            "is_admin": user.get("is_admin", False),
            "api_key_prefix": user.get("api_key_prefix"),
            "scopes": list(user.get("scopes") or []),
            "session_id": session_user.get("session_id")
            or secrets.token_urlsafe(16),
        }
        # Single sign-on sessions expire with their Access token and never hold
        # administration the admin allowlist does not name.
        current_user = restrict_session_user(session, current_user)
        if current_user is None:
            session.clear()
            return None
        if session_user != current_user:
            session["user"] = current_user
        return current_user

    @classmethod
    def _public_user(cls, username: str, user: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": username,
            "username": username,
            "api_key_prefix": user["api_key_prefix"],
            "scopes": list(user.get("scopes") or []),
            "is_admin": user["is_admin"],
            "created_at": serialize_datetime(user["created_at"]),
            "last_login": serialize_datetime(user["last_login"]),
            "last_used_at": serialize_datetime(user["last_used_at"]),
            "last_used_ip": user.get("last_used_ip"),
            "created_by": user.get("created_by"),
            "rotated_at": serialize_datetime(user["rotated_at"]),
            "revoked_at": serialize_datetime(user["revoked_at"]),
            **key_controls.public(user),
        }

    @staticmethod
    def _stored_controls(user: Dict[str, Any]) -> Dict[str, Any]:
        return {name: user.get(name) for name in key_controls.CONTROL_FIELDS}

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
            controls=cls._stored_controls(user),
        )

    @classmethod
    def _update_key_usage(cls, username: str, remote_addr: Optional[str] = None) -> None:
        user = cls._users.get(username)
        if not user:
            return
        last_used_at = _utcnow()
        if user_store.using_d1():
            previous = user.get("last_used_at")
            # Usage metadata is advisory: skip a remote write per request, and never
            # fail an authenticated request because it could not be recorded.
            if (previous and user.get("last_used_ip") == remote_addr
                    and last_used_at - previous < timedelta(seconds=USAGE_WRITE_INTERVAL_SECONDS)):
                return
            try:
                user_store.touch_user(username, serialize_datetime(last_used_at), remote_addr)
            except APIError:
                logger.warning("Could not record API key usage", extra={"username": username})
                return
            user["last_used_at"] = last_used_at
            user["last_used_ip"] = remote_addr
            return
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                try:
                    connection.execute(
                        """
                        UPDATE users
                        SET last_used_at = ?, last_used_ip = ?
                        WHERE username = ?
                        """,
                        (serialize_datetime(last_used_at), remote_addr, username),
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
        if (
            not isinstance(api_key, str)
            or not api_key
            or len(api_key) > MAX_API_KEY_LENGTH
        ):
            return None

        default_username = normalized_username(
            os.environ.get("ADMIN_USERNAME", "admin")
        )
        admin_api_key = os.environ.get("ADMIN_API_KEY")
        if (
            default_username
            and admin_api_key
            and hmac.compare_digest(api_key, admin_api_key)
        ):
            return cls._verify_bootstrap_admin(default_username, api_key, remote_addr)

        if api_key.startswith(KEY_NAMESPACE):
            return verify_integration_key(api_key)

        remembered = cls._remembered_username(api_key)
        user = cls._users.get(remembered) if remembered else None
        if remembered and user and not user.get("revoked_at"):
            cls._update_key_usage(remembered, remote_addr)
            return cls._public_user(remembered, user)

        for username, user in cls._load_users_by_api_key_prefix(
            build_api_key_prefix(api_key)
        ):
            if check_password_hash(user["api_key_hash"], api_key):
                cls._remember_key(api_key, username)
                cls._update_key_usage(username, remote_addr)
                return cls._public_user(username, cls._users[username])

        return None

    @staticmethod
    def _is_bootstrap_record(user: Optional[Dict[str, Any]], api_key: str) -> bool:
        return bool(user and user.get("is_admin") and not user.get("revoked_at")
                    and check_password_hash(user["api_key_hash"], api_key))

    @classmethod
    def _verify_bootstrap_admin(cls, username: str, api_key: str, remote_addr: Optional[str]) -> Dict[str, Any]:
        """ADMIN_API_KEY from the environment authenticates without account storage.

        It is the bootstrap credential that startup writes back to storage, and the edge
        already accepts it from the environment, so a slow or unavailable account store must
        not lock the administrator out. The stored record supplies metadata when it answers.
        """
        user = cls._users.get(username)
        if cls._remembered_username(api_key) != username or not user:
            try:
                user = cls._load_user_by_username(username)
                if user is None and user_store.using_d1():
                    # Startup could not reach D1; write the environment-managed admin now.
                    cls._ensure_default_admin_user()
                    user = cls._users.get(username)
            except APIError:
                logger.warning("Account storage is unavailable; ADMIN_API_KEY authenticated from the environment",
                               extra={"username": username})
                return cls._public_user(username, cls._environment_admin(username, api_key))
            if not cls._is_bootstrap_record(user, api_key):
                logger.warning("The stored admin record does not match ADMIN_API_KEY; startup will restore it",
                               extra={"username": username})
                return cls._public_user(username, cls._environment_admin(username, api_key))
            cls._remember_key(api_key, username)
        cls._update_key_usage(username, remote_addr)
        return cls._public_user(username, cls._users[username])

    @staticmethod
    def _environment_admin(username: str, api_key: str) -> Dict[str, Any]:
        return {"username": username, "api_key_hash": "", "api_key_prefix": build_api_key_prefix(api_key),
                "scopes": list(DEFAULT_ADMIN_SCOPES), "is_admin": True, "created_at": _utcnow(),
                "last_login": None, "last_used_at": None, "last_used_ip": None, "created_by": "system",
                "rotated_at": None, "revoked_at": None, **key_controls.empty()}

    @classmethod
    def authenticate_user(cls, username: str, api_key: str) -> bool:
        """Authenticate a user with username and API key."""
        username = normalized_username(username)
        if (
            username is None
            or not isinstance(api_key, str)
            or not api_key
            or len(api_key) > MAX_API_KEY_LENGTH
        ):
            return False

        user = cls._load_user_by_username(username)
        if not user or user.get("revoked_at") or key_controls.expired(user):
            return False

        if not check_password_hash(user["api_key_hash"], api_key):
            return False

        last_login = _utcnow()
        cls._update_login(username, last_login)
        user = cls._users[username]

        session.clear()
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
        session.clear()

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
    def create_user(cls, username: str, is_admin: bool = False, scopes=None) -> Dict[str, Any]:
        """Create a new user and persist it."""
        return provision_user(cls, username, is_admin, scopes)

    @classmethod
    def delete_user(cls, username: str) -> None:
        """Delete an existing user."""
        current_user = cls._require_admin()
        username = require_valid_username(username)
        reject_local_integration_management(username)
        cls._load_user_by_username(username)
        if username not in cls._users:
            raise APIError("User not found", status_code=404)
        if username == normalized_username(
            os.environ.get("ADMIN_USERNAME", "admin")
        ):
            raise APIError(
                "The environment-managed default admin cannot be deleted",
                status_code=400,
            )
        if username == current_user.get("username"):
            raise APIError("You cannot delete the currently authenticated admin user", status_code=400)
        cls._delete_user_record(username)

    @classmethod
    def rotate_api_key(cls, username: str) -> Dict[str, Any]:
        """Rotate a user's API key."""
        cls._require_admin()
        username = require_valid_username(username)
        reject_local_integration_management(username)
        cls._load_user_by_username(username)
        user = cls._users.get(username)
        if not user:
            raise APIError("User not found", status_code=404)
        if username == normalized_username(
            os.environ.get("ADMIN_USERNAME", "admin")
        ):
            raise APIError(
                "Update ADMIN_API_KEY and restart to rotate the default admin key",
                status_code=400,
            )

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
            controls=cls._stored_controls(user),
        )

        return {
            "id": username,
            "username": username,
            "api_key": new_api_key,
            "api_key_prefix": build_api_key_prefix(new_api_key),
            "rotated_at": serialize_datetime(rotated_at),
        }

    @classmethod
    def set_key_controls(cls, username: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an account's budgets, model allowlist, expiry and address ranges."""
        cls._require_admin()
        username = require_valid_username(username)
        reject_local_integration_management(username)
        user = cls._load_user_by_username(username)
        if not user:
            raise APIError("User not found", status_code=404)
        controls = key_controls.validate(payload)
        if (
            username == normalized_username(os.environ.get("ADMIN_USERNAME", "admin"))
            and (controls["expires_at"] or controls["allowed_ips"])
        ):
            # ADMIN_API_KEY is the break-glass credential; it must keep working everywhere.
            raise APIError(
                "The environment-managed default admin cannot expire or be limited to addresses",
                status_code=400,
            )
        cls._persist_user(
            username=username,
            api_key_hash=user["api_key_hash"],
            api_key_prefix=user["api_key_prefix"],
            scopes=user["scopes"],
            is_admin=user.get("is_admin", False),
            created_at=user["created_at"] or _utcnow(),
            last_login=user.get("last_login"),
            last_used_at=user.get("last_used_at"),
            last_used_ip=user.get("last_used_ip"),
            created_by=user.get("created_by"),
            rotated_at=user.get("rotated_at"),
            revoked_at=user.get("revoked_at"),
            controls=controls,
        )
        return cls._public_user(username, cls._users[username])

    @classmethod
    def get_user_record(cls, username: str) -> Optional[Dict[str, Any]]:
        """An account's public record with its key controls, or None."""
        name = normalized_username(username)
        if name is None:
            return None
        try:
            user = cls._load_user_by_username(name)
        except APIError:
            return None
        return cls._public_user(name, user) if user else None
