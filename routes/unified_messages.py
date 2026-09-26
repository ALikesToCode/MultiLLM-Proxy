"""Unified Anthropic Messages API: POST /v1/messages and /v1/messages/count_tokens.

Claude-style clients send the proxy key as `x-api-key` (or a Bearer token) plus
`anthropic-version`/`anthropic-beta`, which are accepted and not required.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from flask import Response, jsonify, request
from werkzeug.datastructures import ImmutableMultiDict

from error_handlers import get_request_id
from request_validation import json_object_body
from route_helpers import api_auth_required, api_authenticate_only
from routes.protocol_bridge import translation_api_error
from services.protocol_translation import (
    CHAT,
    MESSAGES,
    TranslationError,
    anthropic_error_body,
    error_details,
    is_anthropic_error,
    translate_request,
)
from services.rate_limit_service import RateLimitService

MESSAGES_PATHS = frozenset({"/v1/messages", "/v1/messages/count_tokens"})
MAX_ERROR_BODY_BYTES = 64 * 1024


def anthropic_error_contract(response: Response) -> Response:
    """Give every non-streamed /v1/messages error Anthropic's error envelope."""
    if request.path not in MESSAGES_PATHS or response.status_code < 400 or response.is_streamed:
        return response
    raw = response.get_data()
    try:
        body = json.loads(raw) if raw and len(raw) <= MAX_ERROR_BODY_BYTES else None
    except ValueError:
        body = None
    if is_anthropic_error(body):
        return response
    if body is None:
        body = raw[:2000].decode("utf-8", errors="replace") if raw else ""
    message, error_type, _ = error_details(body, response.status_code)
    response.set_data(
        json.dumps(
            anthropic_error_body(response.status_code, message, error_type, get_request_id())
        )
    )
    response.content_type = "application/json"
    return response


def estimate_message_tokens(payload: dict) -> int:
    """Local estimate with the gateway's rate-limit heuristic (about 4 characters per token)."""
    body = {**payload, "max_tokens": 1, "stream": False}
    try:
        chat = translate_request(body, MESSAGES, CHAT)
    except TranslationError as error:
        raise translation_api_error(error) from error
    return RateLimitService.estimate_input_tokens(chat)


def drop_anthropic_query_flags() -> None:
    """Anthropic SDKs and Claude Code post to /v1/messages?beta=true. The flag
    selects Anthropic's beta surface, so it is never a provider parameter (and
    free pools reject every query parameter)."""
    if "beta" in request.args:
        request.args = ImmutableMultiDict(
            [(name, value) for name, value in request.args.items(multi=True) if name != "beta"]
        )


def register_unified_messages_routes(app, csrf, dispatch: Callable[[dict], Response]) -> None:
    app.after_request(anthropic_error_contract)

    @app.route("/v1/messages", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def unified_messages():
        drop_anthropic_query_flags()
        return dispatch(json_object_body())

    @app.route("/v1/messages/count_tokens", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_authenticate_only
    def unified_messages_count_tokens():
        response = jsonify({"input_tokens": estimate_message_tokens(json_object_body())})
        response.headers["X-MultiLLM-Token-Count"] = "estimate"
        return response
