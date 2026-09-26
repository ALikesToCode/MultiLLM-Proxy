"""Signed, expiring media links, internal job principals and webhook secrets.

One key signs all three. It is derived from MEDIA_SIGNING_SECRET when that is set and
from FLASK_SECRET_KEY otherwise. The Worker derives the same key from the same variable
(worker/media-signing.mjs), so it serves a signed link from R2 without waking the
Container. Rotating the secret invalidates every link, principal and webhook secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time

from error_handlers import APIError

KEY_LABEL = b"multillm-media-v1"
DEFAULT_LINK_TTL_SECONDS = 7 * 86400
MAX_LINK_TTL_SECONDS = 30 * 86400
FILE_ID = re.compile(r"m[a-z]_[A-Za-z0-9_-]{8,120}\Z")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def _secret() -> bytes:
    secret = (os.environ.get("MEDIA_SIGNING_SECRET") or os.environ.get("FLASK_SECRET_KEY") or "").strip()
    if not secret:
        raise APIError("Media signing is not configured", status_code=503)
    return secret.encode("utf-8")


def _mac(label: str, message: str) -> bytes:
    key = hmac.new(_secret(), KEY_LABEL, hashlib.sha256).digest()
    return hmac.new(key, f"{label}:{message}".encode("utf-8"), hashlib.sha256).digest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def link_ttl() -> int:
    try:
        configured = int(os.environ.get("MEDIA_LINK_TTL_SECONDS") or DEFAULT_LINK_TTL_SECONDS)
    except ValueError:
        configured = DEFAULT_LINK_TTL_SECONDS
    return max(60, min(MAX_LINK_TTL_SECONDS, configured))


def sign_file(file_id: str, expires: int) -> str:
    return _b64url(_mac("file", f"{file_id}:{expires}"))


def file_link_params(file_id: str, ttl: int | None = None) -> dict[str, str]:
    expires = int(time.time()) + (ttl or link_ttl())
    return {"expires": str(expires), "signature": sign_file(file_id, expires)}


def verify_file_link(file_id: str, expires: object, signature: object, now: float | None = None) -> bool:
    if not isinstance(expires, str) or not expires.isdigit() or len(expires) > 12:
        return False
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature) or not FILE_ID.fullmatch(file_id):
        return False
    now = time.time() if now is None else now
    if not now <= int(expires) <= now + MAX_LINK_TTL_SECONDS + 60:
        return False
    return hmac.compare_digest(signature, sign_file(file_id, int(expires)))


def issue_principal(kind: str, subject: str, owner: str, ttl: int) -> str:
    """A capability for one job, carrying the owner's identity instead of their key."""
    claims = {"k": kind, "s": subject, "o": owner, "e": int(time.time()) + ttl}
    payload = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{payload}.{_b64url(_mac('principal', payload))}"


def read_principal(token: object, kind: str) -> dict:
    refused = APIError("Invalid job principal", status_code=403)
    if not isinstance(token, str) or len(token) > 2048 or token.count(".") != 1:
        raise refused
    payload, signature = token.split(".")
    if not hmac.compare_digest(signature, _b64url(_mac("principal", payload))):
        raise refused
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        raise refused from None
    if (not isinstance(claims, dict) or claims.get("k") != kind or not isinstance(claims.get("o"), str)
            or not isinstance(claims.get("s"), str) or not isinstance(claims.get("e"), int) or claims["e"] < time.time()):
        raise refused
    return claims


def webhook_secret_bytes(owner: str) -> bytes:
    return _mac("webhook", owner)


def webhook_secret(owner: str) -> str:
    """The owner's Standard Webhooks secret; payloads are signed with the decoded bytes."""
    return "whsec_" + base64.b64encode(webhook_secret_bytes(owner)).decode("ascii")


def webhook_signature(owner: str, message_id: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(webhook_secret_bytes(owner), f"{message_id}.{timestamp}.".encode("utf-8") + body,
                      hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode("ascii")
