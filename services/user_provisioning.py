"""Account provisioning policy shared by the existing Access console."""

import os
from datetime import datetime, timezone

from error_handlers import APIError
from services.auth_primitives import (
    build_api_key_prefix, default_scopes, hash_api_key, require_valid_username, serialize_datetime,
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


def provision_scim_user(auth, username, *, is_admin=False, scopes=None, active=True, persist=None):
    """Prepare a least-privilege account for an atomic provisioning authority.

    The generated credential is discarded. A trusted persistence callback can commit
    the account and its external identity together without an interactive session.
    """
    if is_admin is not False or (scopes is not None and scopes != list(default_scopes(False))):
        raise APIError("SCIM cannot grant administrator or elevated scopes", 400)
    if type(active) is not bool:
        raise APIError("SCIM active must be a boolean", 400)
    username = require_valid_username(username)
    reject_local_integration_management(username)
    reserved = {os.environ.get("ADMIN_USERNAME", "admin").strip(),
                *(name.strip() for name in os.environ.get("ADMIN_USERNAMES", "").split(","))}
    if username in reserved:
        raise APIError("SCIM cannot provision an environment-managed administrator", 400)
    if auth._load_user_by_username(username) is not None:
        raise APIError("User already exists", 409)
    api_key = auth._generate_api_key()
    now = datetime.now(timezone.utc)
    (persist or auth._persist_user)(
        username=username, api_key_hash=hash_api_key(api_key),
        api_key_prefix=build_api_key_prefix(api_key), is_admin=False,
        created_at=now, last_login=None, scopes=default_scopes(False),
        created_by="scim", revoked_at=None if active else now,
    )
    return {"id": username, "username": username, "is_admin": False,
            "scopes": list(default_scopes(False))}
