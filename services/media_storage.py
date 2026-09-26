"""Media I/O through the Worker's private outbound handler (`http://media.internal`).

The Worker fetches caller-supplied image URLs, so a URL can reach only the public
internet and never the Container's private hosts. When the Worker binds an R2 bucket
(MEDIA_BUCKET), generated images and finished videos are stored there and returned as
gateway links (`/v1/media/files/{id}`) signed with an expiry, so they outlive the
provider's short-lived URLs. Without the binding nothing here stores anything.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import secrets

import requests
from flask import Response, g, has_request_context, url_for
from requests.adapters import HTTPAdapter

from error_handlers import APIError
from services.media_signing import FILE_ID, file_link_params
from services.media_urls import public_https_url

logger = logging.getLogger(__name__)

ORIGIN = "http://media.internal"
FETCH_TIMEOUT = (3, 45)
STORE_TIMEOUT = (3, 120)
VIDEO_TIMEOUT = (10, 300)
MAX_FETCH_BYTES = 20 * 1024 * 1024
MAX_IMAGE_BYTES = 50 * 1024 * 1024
MAX_VIDEO_BYTES = 512 * 1024 * 1024
STORED_HEADER = "X-MultiLLM-Media-Stored"
_IMAGE_TYPES = {b"\x89PNG\r\n\x1a\n": "image/png", b"\xff\xd8\xff": "image/jpeg", b"GIF8": "image/gif"}
_DATA_URL_PREFIX = "data:image/"


def enabled() -> bool:
    return os.environ.get("MEDIA_STORAGE_ENABLED", "").strip().lower() == "true"


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


class StorageError(Exception):
    """A storage call failed; the caller keeps the provider's own result instead."""


def new_file_id(prefix: str = "mf") -> str:
    return f"{prefix}_{secrets.token_hex(16)}"


def _metadata(owner: str, kind: str, model: str | None) -> str:
    value = {"owner": owner, "kind": kind, **({"model": model} if model else {})}
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")


def _stored(response: requests.Response) -> dict:
    if response.status_code != 200:
        raise StorageError(_error_code(response))
    try:
        body = response.json()
    except ValueError:
        raise StorageError("invalid_reply") from None
    if not isinstance(body, dict) or not isinstance(body.get("size"), int):
        raise StorageError("invalid_reply")
    return {"id": body.get("id"), "size": body["size"], "content_type": body.get("content_type")}


def _file_url(file_id: str, suffix: str = "") -> str:
    if not FILE_ID.fullmatch(file_id):
        raise StorageError("invalid_file_id")
    return f"{ORIGIN}/v1/files/{file_id}{suffix}"


def put_bytes(file_id: str, data: bytes, content_type: str, *, owner: str, kind: str, model: str | None = None) -> dict:
    try:
        with _session() as session:
            response = session.put(_file_url(file_id), data=data, timeout=STORE_TIMEOUT, allow_redirects=False,
                                   headers={"Content-Type": content_type, "X-Media-Metadata": _metadata(owner, kind, model)})
            return _stored(response)
    except requests.exceptions.RequestException as error:
        raise StorageError(type(error).__name__) from None


class _SizedStream:
    """A body of known length that requests sends with Content-Length, not chunked."""

    def __init__(self, chunks, length: int):
        self._chunks, self._buffer, self._length = iter(chunks), b"", length

    def __len__(self) -> int:
        return self._length

    def read(self, size: int = -1) -> bytes:
        while size < 0 or len(self._buffer) < size:
            chunk = next(self._chunks, None)
            if chunk is None:
                break
            self._buffer += chunk
        if size < 0:
            size = len(self._buffer)
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data


def put_stream(file_id: str, chunks, length: int, content_type: str, *, owner: str, kind: str,
               model: str | None = None) -> dict:
    try:
        with _session() as session:
            response = session.put(_file_url(file_id), data=_SizedStream(chunks, length), timeout=VIDEO_TIMEOUT,
                                   allow_redirects=False,
                                   headers={"Content-Type": content_type, "X-Media-Metadata": _metadata(owner, kind, model)})
            return _stored(response)
    except requests.exceptions.RequestException as error:
        raise StorageError(type(error).__name__) from None


def import_url(file_id: str, url: str, *, owner: str, kind: str, model: str | None = None) -> dict:
    """The Worker downloads a provider URL straight into R2."""
    try:
        with _session() as session:
            response = session.post(_file_url(file_id, "/import"), timeout=STORE_TIMEOUT, allow_redirects=False,
                                    json={"url": url, "metadata": {"owner": owner, "kind": kind,
                                                                   **({"model": model} if model else {})}})
            return _stored(response)
    except requests.exceptions.RequestException as error:
        raise StorageError(type(error).__name__) from None


def stat(file_id: str) -> dict | None:
    """The stored file's size, type and owner, or None when it does not exist."""
    try:
        with _session() as session:
            response = session.get(_file_url(file_id, "/meta"), timeout=FETCH_TIMEOUT, allow_redirects=False)
    except requests.exceptions.RequestException as error:
        raise StorageError(type(error).__name__) from None
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise StorageError(_error_code(response))
    try:
        body = response.json()
    except ValueError:
        raise StorageError("invalid_reply") from None
    return body if isinstance(body, dict) else None


def open_file(file_id: str, range_header: str | None = None) -> requests.Response:
    """A streamed read of the stored file; the caller closes it."""
    session = _session()
    try:
        response = session.get(_file_url(file_id), timeout=VIDEO_TIMEOUT, allow_redirects=False, stream=True,
                                headers={"Range": range_header} if range_header else {})
    except requests.exceptions.RequestException as error:
        session.close()
        raise StorageError(type(error).__name__) from None
    original_close = response.close

    def close() -> None:
        original_close()
        session.close()

    response.close = close  # type: ignore[method-assign]
    return response


def delete(file_id: str) -> bool:
    try:
        with _session() as session:
            response = session.delete(_file_url(file_id), timeout=FETCH_TIMEOUT, allow_redirects=False)
    except requests.exceptions.RequestException as error:
        raise StorageError(type(error).__name__) from None
    if response.status_code != 200:
        raise StorageError(_error_code(response))
    try:
        return response.json().get("deleted") is True
    except (ValueError, AttributeError):
        raise StorageError("invalid_reply") from None


def file_url(file_id: str, ttl: int | None = None) -> str:
    """A signed, expiring gateway link to a stored file."""
    return url_for("media_file", file_id=file_id, _external=True, **file_link_params(file_id, ttl))


def image_type(data: bytes) -> str | None:
    for magic, content_type in _IMAGE_TYPES.items():
        if data.startswith(magic):
            return content_type
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _decode(value: str) -> bytes | None:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def store_image_entries(entries: list, *, owner: str, want_url: bool, model: str | None = None,
                        file_ids: list[str] | None = None) -> tuple[list, list[dict]]:
    """Store generated images and point their entries at gateway links.

    Provider URLs are always stored, because they expire; base64 images are stored when
    the caller asked for URLs. An image that cannot be stored keeps the provider's
    result: it is already generated and may be billed.
    """
    result, stored = [], []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            result.append(entry)
            continue
        file_id = file_ids[index] if file_ids and index < len(file_ids) else new_file_id()
        url, b64 = entry.get("url"), entry.get("b64_json")
        try:
            if isinstance(url, str) and url.startswith(_DATA_URL_PREFIX) and ";base64," in url:
                data = _decode(url.split(",", 1)[1])
                if data is None or image_type(data) is None:
                    raise StorageError("invalid_image")
                info = put_bytes(file_id, data, image_type(data) or "", owner=owner, kind="image", model=model)
            elif isinstance(url, str) and url.startswith("https://"):
                info = import_url(file_id, url, owner=owner, kind="image", model=model)
            elif want_url and isinstance(b64, str):
                data = _decode(b64)
                if data is None or image_type(data) is None or len(data) > MAX_IMAGE_BYTES:
                    raise StorageError("invalid_image")
                info = put_bytes(file_id, data, image_type(data) or "", owner=owner, kind="image", model=model)
            else:
                result.append(entry)
                continue
        except StorageError as error:
            logger.warning("A generated image could not be stored (%s); returning the provider result", error)
            result.append(entry)
            continue
        kept = {name: value for name, value in entry.items() if name not in ("url", "b64_json")}
        result.append({**kept, "url": file_url(file_id), "file_id": file_id})
        stored.append({"id": file_id, "size": info["size"], "content_type": info["content_type"]})
    return result, stored


def _owner() -> str | None:
    user = getattr(g, "authenticated_user", None) if has_request_context() else None
    owner = (user or {}).get("username") or (user or {}).get("id")
    return str(owner) if owner else None


def persist_image_response(response: Response, payload: dict) -> Response:
    """Rewrite a successful image response to gateway links when R2 is bound."""
    owner = _owner()
    if not enabled() or owner is None or response.status_code >= 400 or response.mimetype != "application/json":
        return response
    try:
        body = json.loads(response.get_data())
    except ValueError:
        return response
    entries = body.get("data") if isinstance(body, dict) else None
    if not isinstance(entries, list):
        return response
    want_url = payload.get("response_format") == "url"
    if not any(isinstance(entry, dict) and (entry.get("url") or (want_url and entry.get("b64_json"))) for entry in entries):
        return response
    model = response.headers.get("X-MultiLLM-Auto-Selected-Model") or payload.get("model")
    body["data"], stored = store_image_entries(entries, owner=owner, want_url=want_url,
                                               model=model if isinstance(model, str) else None)
    rewritten = Response(json.dumps(body), status=response.status_code, content_type="application/json")
    for name, value in response.headers.items():
        if name.lower() not in ("content-length", "content-type"):
            rewritten.headers[name] = value
    rewritten.headers[STORED_HEADER] = str(len(stored))
    response.close()
    return rewritten


def video_file_id(job_id: str) -> str:
    return "mv_" + hashlib.sha256(job_id.encode("utf-8")).hexdigest()[:40]


def store_video(file_id: str, url: str, headers: dict, *, owner: str, model: str | None) -> dict | None:
    """Copy a finished video into R2 once; None when its size is unknown or too large."""
    try:
        upstream = requests.get(url, headers=headers, timeout=VIDEO_TIMEOUT, stream=True, allow_redirects=True)
    except requests.exceptions.RequestException:
        return None
    with upstream:
        length = upstream.headers.get("Content-Length", "")
        content_type = upstream.headers.get("Content-Type", "video/mp4").split(";", 1)[0].strip().lower()
        if upstream.status_code != 200 or not length.isdigit() or not 0 < int(length) <= MAX_VIDEO_BYTES:
            return None
        try:
            return put_stream(file_id, upstream.iter_content(1 << 16), int(length), content_type, owner=owner,
                              kind="video", model=model)
        except StorageError as error:
            logger.warning("A finished video could not be stored (%s)", error)
            return None
