"""Registration boundary for authenticated context retrieval."""
from __future__ import annotations

from flask import jsonify

from services.context_pages import ContextPageError, ContextPageService, paging_enabled


def register_context_page_routes(app, *, service: ContextPageService | None = None, authorize=None) -> None:
    """authorize resolves current principal, session, revision, chat grant and retention.

    The callback must authenticate the request; callers never select authority through
    URL/query fields. An absent authority or storage collaborator fails closed.
    """
    service = service or ContextPageService()

    @app.route("/v1/context/pages/<page_id>", methods=["GET"])
    def retrieve_context_page(page_id):
        try:
            if not paging_enabled():
                raise ContextPageError("context_page_not_found", 404)
            if authorize is None:
                raise ContextPageError("context_paging_authority_unavailable")
            authority = authorize()
            if not isinstance(authority, dict) or not {"scope", "retention_policy", "granted"} <= set(authority):
                raise ContextPageError("context_paging_authority_unavailable")
            result = service.retrieve(page_id=page_id, scope=authority["scope"],
                                      retention_policy=authority["retention_policy"], granted=authority["granted"] is True)
            response = jsonify(result)
        except ContextPageError as error:
            response = jsonify({"error": error.code, "message": "Context page retrieval could not be completed."})
            response.status_code = error.status
        response.headers["Cache-Control"] = "private, no-store"
        return response
