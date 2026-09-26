"""Cloudflare Access single sign-on for the dashboard.

The Worker verifies the Access application token and, on the sign-in path only, forwards
an identity assertion signed with CF_ACCESS_PROOF_SECRET; it removes every client copy
of those headers first. This module checks the proof, maps the verified email to a
dashboard account through CF_ACCESS_ALLOWED_EMAILS and bounds single sign-on sessions:
they never hold administration for a username that ADMIN_USERNAME or ADMIN_USERNAMES
does not name, and they end when the Access token would have expired.
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from flask import session

from error_handlers import APIError
from services.auth_primitives import normalized_username

logger = logging.getLogger(__name__)

ACCESS_LOGIN_PATH = "/login/access"
IDENTITY_HEADER = "X-MultiLLM-Access-Identity"
PROOF_HEADER = "X-MultiLLM-Access-Proof"
PROOF_CONTEXT = b"multillm-access-identity-v1."
PROOF_MAX_AGE_SECONDS = 300
MIN_SECRET_LENGTH = 32
SESSION_MAX_SECONDS = 12 * 60 * 60
MAX_IDENTITY_LENGTH = 4096
MAX_EMAIL_LENGTH = 254
AUTH_METHOD = "access"
TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_TEAM_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com\Z")
_EMAIL = re.compile(r"[^\s@\x00-\x1f\x7f]{1,64}@[^\s@\x00-\x1f\x7f]{1,253}\Z")
_REASON = re.compile(r"[a-z][a-z_]{0,31}\Z")
_CLIENT = re.compile(r"[0-9A-Fa-f:.]{2,45}\Z")
_PROOF = re.compile(r"[A-Za-z0-9_-]{43}\Z")


@dataclass(frozen=True)
class AccessAssertion:
    """The Worker's verification result for one sign-in request."""

    verified: bool
    email: Optional[str] = None
    expires_at: Optional[int] = None
    reason: Optional[str] = None
    client: Optional[str] = None


def team_domain() -> Optional[str]:
    value = (os.environ.get("CF_ACCESS_TEAM_DOMAIN") or "").strip().lower().rstrip("/")
    host = value.removeprefix("https://")
    if "://" in host or not _TEAM_HOST.fullmatch(host):
        return None
    return f"https://{host}"


def _proof_secret() -> Optional[bytes]:
    secret = os.environ.get("CF_ACCESS_PROOF_SECRET") or ""
    return secret.encode("utf-8") if len(secret) >= MIN_SECRET_LENGTH else None


def configured() -> bool:
    """Single sign-on is offered only with a valid team domain and a strong proof secret."""
    return team_domain() is not None and _proof_secret() is not None


def sso_only() -> bool:
    """DASHBOARD_SSO_ONLY disables password sign-in, even when single sign-on is not configured."""
    return (os.environ.get("DASHBOARD_SSO_ONLY") or "").strip().lower() in TRUE_VALUES


def logout_url() -> Optional[str]:
    domain = team_domain()
    return f"{domain}/cdn-cgi/access/logout" if domain and configured() else None


def proof(secret: bytes, identity: str) -> str:
    digest = hmac.new(secret, PROOF_CONTEXT + identity.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode_identity(identity: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(identity + "=" * (-len(identity) % 4))
        value = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def read_assertion(headers: Mapping[str, str], method: str, path: str, now: Optional[float] = None) -> Optional[AccessAssertion]:
    """The Worker's assertion for this request, or None unless its proof and binding hold.

    The proof covers the exact header value; the assertion must name this method and
    path and be at most five minutes old, so a leaked header cannot be replayed elsewhere.
    """
    secret = _proof_secret()
    identity = headers.get(IDENTITY_HEADER) or ""
    supplied = headers.get(PROOF_HEADER) or ""
    if (
        secret is None
        or not identity
        or len(identity) > MAX_IDENTITY_LENGTH
        or not identity.isascii()
        or not _PROOF.fullmatch(supplied)
        or not hmac.compare_digest(proof(secret, identity), supplied)
    ):
        return None
    claims = _decode_identity(identity)
    current = time.time() if now is None else now
    if (
        claims is None
        or claims.get("v") != 1
        or claims.get("method") != method
        or claims.get("path") != path
        or type(claims.get("iat")) is not int
        or abs(current - claims["iat"]) > PROOF_MAX_AGE_SECONDS
    ):
        return None
    client = claims.get("client")
    client = client if isinstance(client, str) and _CLIENT.fullmatch(client) else None
    if claims.get("status") == "failed":
        reason = claims.get("reason")
        return AccessAssertion(False, reason=reason if isinstance(reason, str) and _REASON.fullmatch(reason) else "invalid",
                               client=client)
    email, expires_at = claims.get("email"), claims.get("exp")
    if (
        claims.get("status") != "verified"
        or not isinstance(email, str)
        or len(email) > MAX_EMAIL_LENGTH
        or not _EMAIL.fullmatch(email)
        or type(expires_at) is not int
        or expires_at <= current
    ):
        return None
    return AccessAssertion(True, email=email.lower(), expires_at=expires_at, client=client)


def allowed_emails() -> dict[str, str]:
    """Email to username from CF_ACCESS_ALLOWED_EMAILS.

    Entries are comma-separated. ``person@example.com=alice`` signs in as ``alice``; a bare
    ``person@example.com`` signs in as the account named by that email address. Anything
    else is ignored, so an unlisted email never matches.
    """
    mapping: dict[str, str] = {}
    for entry in (os.environ.get("CF_ACCESS_ALLOWED_EMAILS") or "").split(","):
        email, separator, username = entry.strip().partition("=")
        email = email.strip().lower()
        username = normalized_username(username if separator else email)
        if not email or len(email) > MAX_EMAIL_LENGTH or not _EMAIL.fullmatch(email) or username is None:
            continue
        mapping.setdefault(email, username)
    return mapping


def username_for_email(email: str) -> Optional[str]:
    return allowed_emails().get(email.lower()) if isinstance(email, str) else None


def admin_usernames() -> frozenset[str]:
    """ADMIN_USERNAME (default admin) and ADMIN_USERNAMES, as the Worker reads them."""
    names = [os.environ.get("ADMIN_USERNAME", "admin"), *(os.environ.get("ADMIN_USERNAMES") or "").split(",")]
    return frozenset(name for name in (normalized_username(value) for value in names) if name)


def _limited(user: dict[str, Any]) -> dict[str, Any]:
    if not user.get("is_admin") or user.get("username") in admin_usernames():
        return user
    return {**user, "is_admin": False, "scopes": [scope for scope in user.get("scopes") or [] if scope != "admin"]}


def restrict_session_user(active_session, user: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Apply single sign-on limits to a revalidated session user, or None to end the session."""
    method = active_session.get("auth_method")
    if sso_only() and method != AUTH_METHOD:
        return None
    if method != AUTH_METHOD:
        return user
    expires_at = active_session.get("auth_expires_at")
    if type(expires_at) is not int or expires_at <= time.time() or not configured():
        return None
    return _limited(user)


def sign_in(auth, username: str, assertion: AccessAssertion, now: Optional[float] = None) -> Optional[dict[str, Any]]:
    """Start a new dashboard session for a verified, allowlisted identity.

    The previous session, including its CSRF token, is discarded first. The session ends
    when the Access token expires, and after twelve hours at most.
    """
    user = auth._load_user_by_username(username)
    if not user or user.get("revoked_at") or not assertion.verified or assertion.expires_at is None:
        return None
    try:
        auth._update_login(username, datetime.now(timezone.utc))
        user = auth._users.get(username, user)
    except APIError:
        logger.warning("Could not record the single sign-on time", extra={"username": username})
    current = time.time() if now is None else now
    session.clear()
    session["user"] = _limited({
        "username": username,
        "is_admin": bool(user.get("is_admin", False)),
        "api_key_prefix": user.get("api_key_prefix"),
        "scopes": list(user.get("scopes") or []),
        "session_id": secrets.token_urlsafe(16),
    })
    session["authenticated"] = True
    session["auth_method"] = AUTH_METHOD
    session["auth_expires_at"] = int(min(assertion.expires_at, current + SESSION_MAX_SECONDS))
    return session["user"]
