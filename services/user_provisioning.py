"""Account provisioning policy shared by the existing Access console."""

from datetime import datetime, timezone

from error_handlers import APIError
from services.auth_primitives import (
    build_api_key_prefix, default_scopes, require_valid_username, serialize_datetime,
)
from services.intelligence_auth import reject_local_integration_management

USER_SCOPES = frozenset({"chat", "models", "knowledge:read", "knowledge:manage"})


def account_scopes(is_admin, scopes):
    if scopes is None:
        return default_scopes(is_admin)
    if is_admin:
        raise APIError("Administrator accounts use the standard administrator scopes", 400)
    if (not isinstance(scopes, list) or not scopes or len(scopes) > len(USER_SCOPES)
            or any(not isinstance(scope, str) or scope not in USER_SCOPES for scope in scopes)
            or len(set(scopes)) != len(scopes)):
        raise APIError("Choose at least one supported account permission", 400)
    return tuple(sorted(scopes))


def create_user(auth, username, is_admin=False, scopes=None):
    """Create one persisted principal; callers cannot elevate through a scope string."""
    current_user = auth._require_admin()
    username = require_valid_username(username)
    reject_local_integration_management(username)
    granted_scopes = account_scopes(is_admin, scopes)
    if auth._load_user_by_username(username) is not None:
        raise APIError("User already exists", status_code=409)
    api_key = auth._generate_api_key()
    created_at = datetime.now(timezone.utc)
    auth._persist_user_with_api_key(
        username=username, api_key=api_key, is_admin=is_admin,
        created_at=created_at, last_login=None, scopes=granted_scopes,
        created_by=current_user.get("username"),
    )
    return {
        "id": username, "username": username, "api_key": api_key,
        "api_key_prefix": build_api_key_prefix(api_key), "scopes": list(granted_scopes),
        "is_admin": is_admin, "created_at": serialize_datetime(created_at), "last_login": None,
    }
