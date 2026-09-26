"""Media I/O through the Worker's private outbound handler (`http://media.internal`).

The Worker fetches caller-supplied image URLs, so a URL can reach only the public
internet and never the Container's private hosts.
"""

from __future__ import annotations

import json

import requests
from requests.adapters import HTTPAdapter

from error_handlers import APIError
from services.media_urls import public_https_url

ORIGIN = "http://media.internal"
FETCH_TIMEOUT = (3, 45)
MAX_FETCH_BYTES = 20 * 1024 * 1024


def _session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.mount("http://", HTTPAdapter(max_retries=0))
    return session


def _error_code(response: requests.Response) -> str:
    try:
        error = json.loads(response.content).get("error")
    except (ValueError, AttributeError):
        return "media_unavailable"
    code = error.get("code") if isinstance(error, dict) else None
    return code if isinstance(code, str) and len(code) <= 64 else "media_unavailable"


def _read(response: requests.Response, limit: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > limit:
        raise APIError("The image is too large", status_code=413)
    body = bytearray()
    for chunk in response.iter_content(65536):
        body.extend(chunk)
        if len(body) > limit:
            raise APIError("The image is too large", status_code=413)
    return bytes(body)


def fetch_public(url: str, *, max_bytes: int = MAX_FETCH_BYTES, field: str = "image URL") -> tuple[bytes, str]:
    """Download a public HTTPS image through the Worker; returns its bytes and media type."""
    url = public_https_url(url, field)
    with _session() as session:
        try:
            with session.post(f"{ORIGIN}/v1/fetch", json={"url": url, "max_bytes": max_bytes}, timeout=FETCH_TIMEOUT,
                              allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    code = _error_code(response)
                    raise APIError(f"The {field} could not be fetched ({code})",
                                   status_code=413 if response.status_code == 413 else 400)
                return _read(response, max_bytes), response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        except requests.exceptions.RequestException:
            raise APIError(f"The {field} could not be fetched; send the image as a data URL or file upload",
                           status_code=503) from None
