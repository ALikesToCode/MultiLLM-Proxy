"""Restrict durable integration credentials to policy-controlled gateway routes."""

from flask import request
from error_handlers import APIError


def authorize_integration_route(user):
    identity = user.get("id")
    username = user.get("username")
    if not any(
        isinstance(value, str) and value.startswith("integration:")
        for value in (identity, username)
    ):
        return
    if request.path == "/mcp" or request.path.startswith("/v1/knowledge/"):
        # Knowledge routes enforce knowledge:read/knowledge:manage themselves.
        return
    route = (request.method, request.path)
    allowed = route in {
        ("GET", "/v1/models"),
        ("POST", "/intelligence/v1/chat/completions"),
        ("POST", "/v1/audio/transcriptions"),
        ("POST", "/v1/audio/speech"),
        ("POST", "/v1/embeddings"),
    }
    if route == ("POST", "/v1/chat/completions"):
        payload = request.get_json(silent=True)
        # Keep this discriminator aligned with dispatch_unified_chat_completion.
        allowed = isinstance(payload, dict) and (
            payload.get("model") == "auto:intelligence" or "routing" in payload
        )
    if not allowed:
        raise APIError(
            "Integration credentials require intelligence gateway routing",
            403,
            {"error": "integration_route_forbidden"},
        )
