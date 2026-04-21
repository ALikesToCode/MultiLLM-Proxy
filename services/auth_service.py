import logging
import os
import secrets
import sqlite3
import string
import subprocess
import json
import shutil
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account
from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from error_handlers import APIError

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthService:
    """Service for handling user authentication and API key management."""

    _users: Dict[str, Dict[str, Any]] = {}
    _api_keys: Dict[str, str] = {}
    _google_token: Optional[str] = None
    _google_token_expiry: Optional[datetime] = None
    _google_token_lock = threading.Lock()
    _storage_lock = threading.Lock()
    _storage_path: Optional[Path] = None
    _jwt_secret: Optional[str] = os.environ.get("JWT_SECRET")

    @classmethod
    def _default_storage_path(cls) -> Path:
        return Path(__file__).resolve().parent.parent / "instance" / "auth.sqlite3"

    @classmethod
    def _get_storage_path(cls) -> Path:
        if cls._storage_path is None:
            configured_path = os.environ.get("AUTH_DB_PATH")
            cls._storage_path = Path(configured_path) if configured_path else cls._default_storage_path()
        return cls._storage_path

    @classmethod
    def _connect(cls) -> sqlite3.Connection:
        storage_path = cls._get_storage_path()
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(storage_path)
        connection.row_factory = sqlite3.Row
        return connection

    @classmethod
    def _ensure_storage(cls) -> None:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        api_key TEXT NOT NULL,
                        api_key_hash TEXT NOT NULL,
                        is_admin INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        last_login TEXT
                    )
                    """
                )
                connection.commit()

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

    @classmethod
    def _row_to_user(cls, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "username": row["username"],
            "api_key": row["api_key"],
            "api_key_hash": row["api_key_hash"],
            "is_admin": bool(row["is_admin"]),
            "created_at": cls._deserialize_datetime(row["created_at"]),
            "last_login": cls._deserialize_datetime(row["last_login"]),
        }

    @classmethod
    def _reload_user_cache(cls) -> None:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT username, api_key, api_key_hash, is_admin, created_at, last_login
                    FROM users
                    ORDER BY username
                    """
                ).fetchall()
        cls._users = {
            row["username"]: cls._row_to_user(row)
            for row in rows
        }

    @classmethod
    def _persist_user(
        cls,
        username: str,
        api_key: str,
        is_admin: bool,
        created_at: datetime,
        last_login: Optional[datetime] = None,
    ) -> None:
        with cls._storage_lock:
            with closing(cls._connect()) as connection:
                connection.execute(
                    """
                    INSERT INTO users (username, api_key, api_key_hash, is_admin, created_at, last_login)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        api_key = excluded.api_key,
                        api_key_hash = excluded.api_key_hash,
                        is_admin = excluded.is_admin,
                        created_at = excluded.created_at,
                        last_login = excluded.last_login
                    """,
                    (
                        username,
                        api_key,
                        generate_password_hash(api_key),
                        int(is_admin),
                        cls._serialize_datetime(created_at),
                        cls._serialize_datetime(last_login),
                    ),
                )
                connection.commit()
        cls._reload_user_cache()

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
        if existing_user and existing_user.get("api_key") == default_api_key and existing_user.get("is_admin"):
            return

        created_at = existing_user.get("created_at") if existing_user else _utcnow()
        last_login = existing_user.get("last_login") if existing_user else None
        cls._persist_user(
            username=default_username,
            api_key=default_api_key,
            is_admin=True,
            created_at=created_at,
            last_login=last_login,
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
            "palm",
            "together",
            "nineteen",
        ]:
            env_key = f"{provider.upper()}_API_KEY"
            api_key = os.environ.get(env_key)
            if api_key:
                cls._api_keys[provider] = api_key

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
    def authenticate_user(cls, username: str, api_key: str) -> bool:
        """Authenticate a user with username and API key."""
        user = cls._users.get(username)
        if not user:
            return False

        if not check_password_hash(user["api_key_hash"], api_key):
            return False

        last_login = _utcnow()
        cls._persist_user(
            username=username,
            api_key=user["api_key"],
            is_admin=user.get("is_admin", False),
            created_at=user["created_at"] or last_login,
            last_login=last_login,
        )

        session["user"] = {
            "username": username,
            "is_admin": user.get("is_admin", False),
            "api_key": api_key,
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
        return [
            {
                "id": username,
                "username": username,
                "api_key": user["api_key"],
                "is_admin": user["is_admin"],
                "created_at": cls._serialize_datetime(user["created_at"]),
                "last_login": cls._serialize_datetime(user["last_login"]),
            }
            for username, user in sorted(cls._users.items())
        ]

    @classmethod
    def count_users(cls) -> int:
        """Return the total number of persisted users."""
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
        cls._persist_user(
            username=username,
            api_key=api_key,
            is_admin=is_admin,
            created_at=created_at,
            last_login=None,
        )

        return {
            "id": username,
            "username": username,
            "api_key": api_key,
            "is_admin": is_admin,
            "created_at": cls._serialize_datetime(created_at),
            "last_login": None,
        }

    @classmethod
    def delete_user(cls, username: str) -> None:
        """Delete an existing user."""
        current_user = cls._require_admin()
        if username not in cls._users:
            raise APIError("User not found", status_code=404)
        if username == current_user.get("username"):
            raise APIError("You cannot delete the currently authenticated admin user", status_code=400)
        cls._delete_user_record(username)

    @classmethod
    def rotate_api_key(cls, username: str) -> Dict[str, Any]:
        """Rotate a user's API key."""
        cls._require_admin()
        user = cls._users.get(username)
        if not user:
            raise APIError("User not found", status_code=404)

        new_api_key = cls._generate_api_key()
        cls._persist_user(
            username=username,
            api_key=new_api_key,
            is_admin=user["is_admin"],
            created_at=user["created_at"] or _utcnow(),
            last_login=user["last_login"],
        )

        return {
            "id": username,
            "username": username,
            "api_key": new_api_key,
        }
