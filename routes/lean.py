"""Lean mode responses: report headers and the protocol's own "prompt is too long" error."""

from __future__ import annotations

import json

from flask import Response, jsonify, request

from error_handlers import get_request_id
from services.lean_mode import LeanPromptTooLong, lean_response_headers
from services.protocol_translation import anthropic_error_body


def prompt_too_long_response(error: LeanPromptTooLong):
    """Refuse in the shape each harness treats as a context overflow, so it compacts.

    Claude Code compacts on Anthropic's "prompt is too long" error. OpenAI-style
    clients match `context_length_exceeded`; Codex reads it from a streamed
    `response.failed` event.
    """
    request_id = get_request_id()
    if request.path.startswith("/v1/messages"):
        return jsonify(anthropic_error_body(400, str(error), "invalid_request_error", request_id)), 400
    message = (
        f"This model's maximum context length is {error.limit} tokens. However, your "
        f"messages resulted in {error.tokens} tokens ({error}). Compact the "
        "conversation and try again."
    )
    payload = request.get_json(silent=True)
    if request.path == "/v1/responses" and isinstance(payload, dict) and payload.get("stream"):
        event = {
            "type": "response.failed",
            "sequence_number": 0,
            "response": {
                "object": "response",
                "status": "failed",
                "error": {"code": "context_length_exceeded", "message": message},
            },
        }
        return Response(
            f"event: response.failed\ndata: {json.dumps(event)}\n\n",
            mimetype="text/event-stream",
        )
    error_body = {
        "message": message,
        "type": "invalid_request_error",
        "param": "messages",
        "code": "context_length_exceeded",
    }
    return jsonify({"error": error_body, "request_id": request_id}), 400


def register_lean_routes(app) -> None:
    app.after_request(lean_response_headers)
    app.register_error_handler(LeanPromptTooLong, prompt_too_long_response)
