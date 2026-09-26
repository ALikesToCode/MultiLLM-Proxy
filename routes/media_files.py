"""Stored media files: owner access, fresh links and deletion (docs/media-storage.md).

The Worker answers signed links from R2 itself. A request with an API key reaches this
route, which serves the file to the key's owner (or an administrator).
"""

from __future__ import annotations

from flask import Response, g, jsonify, request

from error_handlers import APIError, get_request_id
from route_helpers import api_authenticate_only
from services import media_storage
from services.media_signing import FILE_ID, file_link_params

_COPIED_HEADERS = ("Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "ETag")


def unavailable(code: str, message: str) -> Response:
    """A 503 that keeps its explanation (APIError hides messages of server errors)."""
    response = jsonify({"error": code, "message": message, "request_id": get_request_id()})
    response.status_code = 503
    return response


def stream_stored_file(file_id: str, cache_control: str) -> Response:
    try:
        upstream = media_storage.open_file(file_id, request.headers.get("Range"))
    except media_storage.StorageError:
        return unavailable("media_storage_unavailable", "Media storage could not be reached; try again.")
    if upstream.status_code not in (200, 206):
        upstream.close()
        if upstream.status_code == 404:
            raise APIError("File not found", status_code=404)
        return unavailable("media_storage_unavailable", "Media storage could not be reached; try again.")

    def generate():
        try:
            yield from upstream.iter_content(1 << 16)
        finally:
            upstream.close()

    if request.method == "HEAD":
        upstream.close()
    response = Response(b"" if request.method == "HEAD" else generate(), status=upstream.status_code)
    for name in _COPIED_HEADERS:
        if name in upstream.headers:
            response.headers[name] = upstream.headers[name]
    response.headers["Cache-Control"] = cache_control
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _is_admin(user: dict) -> bool:
    return bool(user.get("is_admin")) or "admin" in (user.get("scopes") or [])


def _owned_file(file_id: str) -> dict:
    user = g.authenticated_user
    try:
        meta = media_storage.stat(file_id) if FILE_ID.fullmatch(file_id) else None
    except media_storage.StorageError:
        raise APIError("Media storage could not be reached", status_code=503,
                       payload={"error": "media_storage_unavailable"}) from None
    if meta is None or (meta.get("owner") != user.get("username") and not _is_admin(user)):
        raise APIError("File not found", status_code=404)
    return meta


def register_media_file_routes(app, csrf) -> None:
    @api_authenticate_only
    def owner_file(file_id: str):
        meta = _owned_file(file_id)
        if request.method == "DELETE":
            try:
                deleted = media_storage.delete(file_id)
            except media_storage.StorageError:
                return unavailable("media_storage_unavailable", "Media storage could not be reached; try again.")
            return jsonify({"id": file_id, "object": "media.file", "deleted": deleted})
        if request.args.get("format") == "json":
            # A fresh signed link for a file the caller owns.
            return jsonify({"id": file_id, "object": "media.file", "bytes": meta.get("size"),
                            "content_type": meta.get("content_type"), "kind": meta.get("kind"),
                            "model": meta.get("model"), "created_at": meta.get("uploaded"),
                            "url": media_storage.file_url(file_id), "expires_at": int(file_link_params(file_id)["expires"])})
        return stream_stored_file(file_id, "private, no-store")

    @app.route("/v1/media/files/<file_id>", methods=["GET", "HEAD", "DELETE", "OPTIONS"])
    @csrf.exempt
    def media_file(file_id: str):
        # Signed links never get here: the Worker serves them from R2 (worker/media-files.mjs).
        if request.method != "OPTIONS" and not media_storage.enabled():
            raise APIError("Media storage is not configured on this deployment", status_code=404,
                           payload={"error": "media_storage_not_configured"})
        return owner_file(file_id)
