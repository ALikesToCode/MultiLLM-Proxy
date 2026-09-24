"""Durable, nonadministrative integration principals on the private D1 domain."""

import os
import re

from werkzeug.security import check_password_hash
from error_handlers import APIError

KEY_NAMESPACE = "mllm_intelligence_"
PRINCIPAL_NAMESPACE = "integration:"
SCOPES = frozenset({
    "chat", "models", "audio", "embeddings", "knowledge:read", "knowledge:manage",
})
KEY_PATTERN = re.compile(r"mllm_intelligence_[A-Za-z0-9_-]{32,128}\Z")
ID_PATTERN = re.compile(r"integration:[a-z][a-z0-9_-]{0,63}\Z")
HASH_PATTERN = re.compile(r"scrypt:32768:8:1\$[A-Za-z0-9]{8,32}\$[a-f0-9]{128}\Z")


def reject_local_integration_management(username):
    if username.startswith(PRINCIPAL_NAMESPACE):
        raise APIError(
            "Integration principals require durable credential management",
            403,
            {"error": "integration_management_required"},
        )


def verify_integration_key(api_key):
    """Never fall back to local users, including when the durable backend is disabled."""
    if os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip().lower() != "d1":
        return None
    if not KEY_PATTERN.fullmatch(api_key):
        return None
    prefix = api_key[: len(KEY_NAMESPACE) + 16]
    try:
        from services.intelligence_d1_store import request_private_intelligence

        response = request_private_intelligence(
            {"version": 1, "operation": "lookup", "keyPrefix": prefix}, endpoint="auth"
        )
        if (
            not isinstance(response, dict)
            or set(response) != {"version", "principal"}
            or type(response["version"]) is not int
            or response["version"] != 1
        ):
            raise ValueError("Invalid auth envelope")
        principal = response["principal"]
        if principal is None:
            return None
        required = {
            "id",
            "scopes",
            "credentialVersion",
            "createdAt",
            "revokedAt",
            "keyPrefix",
            "keyHash",
        }
        if not isinstance(principal, dict) or set(principal) != required:
            raise ValueError("Invalid principal")
        scopes = principal["scopes"]
        if (
            not isinstance(principal["id"], str)
            or not ID_PATTERN.fullmatch(principal["id"])
            or not isinstance(scopes, list)
            or not scopes
            or len(scopes) > len(SCOPES)
            or any(
                not isinstance(scope, str) or scope not in SCOPES for scope in scopes
            )
            or len(set(scopes)) != len(scopes)
            or type(principal["credentialVersion"]) is not int
            or principal["credentialVersion"] < 1
            or principal["keyPrefix"] != prefix
            or not isinstance(principal["keyHash"], str)
            or not HASH_PATTERN.fullmatch(principal["keyHash"])
            or not isinstance(principal["createdAt"], str)
            or principal["revokedAt"] is not None
            and not isinstance(principal["revokedAt"], str)
        ):
            raise ValueError("Invalid principal")
        if principal["revokedAt"] is not None or not check_password_hash(
            principal["keyHash"], api_key
        ):
            return None
        return {
            "id": principal["id"],
            "username": principal["id"],
            "is_admin": False,
            "api_key_prefix": prefix,
            "scopes": scopes,
            "created_at": principal["createdAt"],
            "last_login": None,
            "last_used_at": None,
            "last_used_ip": None,
            "created_by": "integration",
            "rotated_at": None,
            "revoked_at": None,
        }
    except Exception:
        raise APIError(
            "Integration authentication is unavailable",
            503,
            {"error": "integration_auth_unavailable"},
        ) from None
