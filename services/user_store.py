"""Dashboard accounts in the Worker's D1 database, reached through the private outbound handler.

Container disk is reset whenever the Container sleeps or is replaced, so accounts and
key hashes live in D1 when the Worker selects AUTH_STORAGE_BACKEND=d1. The Worker runs
fixed statements only; no SQL crosses this boundary. Failures never fall back to local
SQLite: an unavailable store is reported as such.
"""

import os

from error_handlers import APIError
from services.intelligence_d1_store import request_private_intelligence

USER_FIELDS = (
    "username", "api_key_hash", "api_key_prefix", "scopes", "is_admin", "created_at",
    "last_login", "last_used_at", "last_used_ip", "created_by", "rotated_at", "revoked_at",
)
_REQUIRED_TEXT = ("username", "api_key_hash", "api_key_prefix", "scopes", "created_at")
_OPTIONAL_TEXT = ("last_login", "last_used_at", "last_used_ip", "created_by", "rotated_at", "revoked_at")
PAGE_SIZE = 200


def using_d1():
    backend = os.environ.get("AUTH_STORAGE_BACKEND", "").strip().lower()
    if backend not in {"", "sql", "d1"}:
        raise RuntimeError("AUTH_STORAGE_BACKEND must be sql or d1")
    return backend == "d1"


def unavailable():
    return APIError("Account storage is unavailable", 503, {"error": "account_storage_unavailable"})


def _call(operation, **values):
    try:
        return request_private_intelligence({"operation": operation, **values}, endpoint="users")
    except Exception:
        raise unavailable() from None


def _row(value):
    if (
        not isinstance(value, dict)
        or set(value) != set(USER_FIELDS)
        or any(not isinstance(value[name], str) for name in _REQUIRED_TEXT)
        or any(value[name] is not None and not isinstance(value[name], str) for name in _OPTIONAL_TEXT)
        or type(value["is_admin"]) is not int
        or value["is_admin"] not in (0, 1)
    ):
        raise unavailable()
    return value


def _rows(value, limit=PAGE_SIZE):
    if not isinstance(value, list) or len(value) > limit:
        raise unavailable()
    return [_row(item) for item in value]


def list_users():
    users, after = [], None
    while True:
        page = _rows(_call("list", after=after, limit=PAGE_SIZE).get("users"))
        users.extend(page)
        if len(page) < PAGE_SIZE:
            return users
        after = page[-1]["username"]


def get_user(username):
    response = _call("get", username=username)
    if "user" not in response:
        raise unavailable()
    return None if response["user"] is None else _row(response["user"])


def users_by_prefix(prefix):
    return _rows(_call("by_prefix", prefix=prefix).get("users"))


def upsert_user(user):
    if _call("upsert", user={name: user[name] for name in USER_FIELDS}).get("stored") is not True:
        raise unavailable()


def delete_user(username):
    _call("delete", username=username)


def touch_user(username, last_used_at, last_used_ip):
    _call("touch", username=username, last_used_at=last_used_at, last_used_ip=last_used_ip)
