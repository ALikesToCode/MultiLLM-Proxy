"""Caller-supplied URLs the gateway fetches or calls: public HTTPS hosts only.

This mirrors `publicHost` in worker/knowledge/contracts.mjs, which the Worker applies again
before it fetches anything. Private, loopback and reserved names never pass, and IP
literals are refused, so a URL cannot aim a fetch or a webhook at internal services
(including the Container's private `*.internal` hosts).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from error_handlers import APIError

MAX_URL_LENGTH = 2048
_PUBLIC_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_RESERVED_HOST = re.compile(r"(?:^|\.)(?:localhost|local|internal|lan|home|test|invalid|example|onion)\Z")


def public_host(hostname: str | None) -> bool:
    return (isinstance(hostname, str) and len(hostname) <= 253 and bool(_PUBLIC_HOST.match(hostname))
            and not _RESERVED_HOST.search(hostname))


def public_https_url(value: object, field: str) -> str:
    """The URL when it names a public HTTPS host without credentials; otherwise a 400."""
    invalid = APIError(f"{field} must be an https URL on a public host, without credentials or a port",
                       status_code=400)
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH or re.search(r"[\x00-\x20\x7f]", value):
        raise invalid
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise invalid from None
    if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or port not in (None, 443) or not public_host((parsed.hostname or "").rstrip("."))):
        raise invalid
    return value
