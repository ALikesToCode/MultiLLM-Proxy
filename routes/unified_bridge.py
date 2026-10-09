"""Managed conversion dispatch and opt-in, content-free diagnostics."""

from __future__ import annotations

from functools import wraps

from flask import Response, g, has_request_context, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_authenticate_only, request_body_limit
from routes.protocol_bridge import (
    translate_downstream_response, translation_api_error, translation_request_headers,
)
from services import key_controls
from services.conversion_diagnostics import (
    BODY_LIMIT, combine_reports, report_headers,
)
from services.protocol_translation import CHAT, PROTOCOLS, TranslationError
from services.protocol_extras import managed_request_report
from services.managed_turn import emit_managed_request


def _add_prompt_cache_headers(
    response: Response,
    decision,
) -> Response:
    response.headers["X-MultiLLM-Prompt-Cache"] = decision.status
    response.headers["X-MultiLLM-Prompt-Cache-Mode"] = decision.mode
    response.headers["X-MultiLLM-Prompt-Cache-Estimated-Tokens"] = str(
        decision.estimated_input_tokens
    )
    return response


def diagnostics_requested() -> bool:
    return has_request_context() and request.headers.get("X-MultiLLM-Conversion-Report") == "1"


def record_conversion(report: dict) -> None:
    if diagnostics_requested():
        reports = getattr(g, "conversion_reports", None)
        if reports is None:
            reports = g.conversion_reports = []
        reports.append(report)


def record_request_conversion(payload: dict, source: str, target: str) -> None:
    if diagnostics_requested():
        record_conversion(managed_request_report(payload, source, target))


def with_chat_conversion_report(view):
    """Describe the current Chat hop even when the cache serves it without dispatch."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if diagnostics_requested():
            payload = request.get_json(silent=True)
            if isinstance(payload, dict):
                record_request_conversion(payload, CHAT, CHAT)
        return view(*args, **kwargs)
    return wrapper


def dispatch_translated_protocol(
    app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload: dict,
    protocol: str, *, dispatch_chat,
):
    """Serve Responses or Messages through an explicit Chat dispatcher collaborator."""
    record_request_conversion(payload, protocol, CHAT)
    try:
        chat_payload = emit_managed_request(payload, protocol, CHAT)
    except TranslationError as error:
        raise translation_api_error(error) from error
    if "routing" in payload:
        chat_payload["routing"] = payload["routing"]
    response = dispatch_chat(
        app, auth_service_cls, metrics_service_cls, proxy_service_cls, chat_payload,
        request_headers=translation_request_headers(request.headers),
    )
    return translate_downstream_response(
        response, source=CHAT, target=protocol, stream=bool(chat_payload.get("stream")),
        model=payload.get("model"), request_payload=payload,
    )


def register_conversion_routes(app, csrf) -> None:
    @app.after_request
    def conversion_headers(response):
        reports = getattr(g, "conversion_reports", None)
        if diagnostics_requested() and reports:
            response.headers.update(report_headers(combine_reports(*reports)))
        return response

    @app.route("/v1/conversion/report", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    @request_body_limit(lambda: BODY_LIMIT + 1)
    def conversion_report():
        # Read one sentinel byte so a lengthless, truncated body cannot evade the limit.
        if request.content_length is not None and request.content_length > BODY_LIMIT:
            raise RequestEntityTooLarge()
        if len(request.get_data(cache=True)) > BODY_LIMIT:
            raise RequestEntityTooLarge()
        body = json_object_body()
        source, target = body.get("source_protocol"), body.get("target_protocol")
        if not isinstance(source, str) or not isinstance(target, str) or source not in PROTOCOLS or target not in PROTOCOLS:
            raise APIError("source_protocol and target_protocol must be chat, responses or messages", 400)
        payload = body.get("request")
        if not isinstance(payload, dict):
            raise APIError("request must be a JSON object", 400)
        model = payload.get("model")
        if not isinstance(model, str) or not model.strip():
            raise APIError("request.model must be a non-empty model ID", 400)
        if not key_controls.model_allowed(g.authenticated_user, model):
            raise APIError("This API key is not allowed to use the requested model", 403,
                           {"error": "model_not_allowed"})
        report = managed_request_report(payload, source, target)
        return jsonify(report), 400 if report["fidelity"] == "unsupported" else 200
