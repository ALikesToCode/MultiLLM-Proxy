"""Registration boundary for authenticated context retrieval."""
from __future__ import annotations

from functools import wraps

from flask import current_app, jsonify, request

from services.context_pages import ContextPageError, ContextPageService, paging_enabled


def register_context_page_routes(app, *, service: ContextPageService | None = None, authorize=None,
                                 authenticate=None) -> None:
    """authorize resolves current principal, session, revision, chat grant and retention.

    The callback must authenticate the request; callers never select authority through
    URL/query fields. An absent authority or storage collaborator fails closed.
    """
    if app.extensions.get("context_page_routes_registered"):
        return
    service = service or ContextPageService()
    app.extensions.setdefault("context_page_service", service)
    app.extensions["context_page_routes_registered"] = True

    def gate_disabled_context_pages():
        if request.endpoint == "retrieve_context_page" and not paging_enabled():
            return jsonify({"error": "context_page_not_found",
                            "message": "Context page retrieval could not be completed."}), 404
        return None
    app.before_request_funcs.setdefault(None, []).insert(0, gate_disabled_context_pages)

    def guarded(view):
        authenticated = authenticate(view) if authenticate is not None else view
        @wraps(view)
        def wrapped(*args, **kwargs):
            # Preserve the disabled 404 before authentication/accounting work.
            return authenticated(*args, **kwargs) if paging_enabled() else view(*args, **kwargs)
        return wrapped

    @app.route("/v1/context/pages/<page_id>", methods=["GET"])
    @guarded
    def retrieve_context_page(page_id):
        try:
            if not paging_enabled():
                raise ContextPageError("context_page_not_found", 404)
            if authorize is None:
                raise ContextPageError("context_paging_authority_unavailable")
            authority = authorize()
            if not isinstance(authority, dict) or not {"scope", "retention_policy", "granted"} <= set(authority):
                raise ContextPageError("context_paging_authority_unavailable")
            result = current_app.extensions["context_page_service"].retrieve(page_id=page_id, scope=authority["scope"],
                                      retention_policy=authority["retention_policy"], granted=authority["granted"] is True)
            response = jsonify(result)
        except ContextPageError as error:
            response = jsonify({"error": error.code, "message": "Context page retrieval could not be completed."})
            response.status_code = error.status
        response.headers["Cache-Control"] = "private, no-store"
        return response
