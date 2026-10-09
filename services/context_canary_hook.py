"""Authenticated canary opt-in without annotating caller-owned request data."""
import os

from flask import g, request

from services.context_canary import resolve_policy


def context_canary_request_hook():
    from services.gateway_extensions import managed_generation_request
    if not managed_generation_request():
        return None
    user = getattr(g, "authenticated_user", None) or {}
    if not user:
        return None
    key_scope = str(user.get("id") or user.get("username") or "")
    if resolve_policy(os.environ, route=request.path, key_scope=key_scope) is None:
        return None
    protocol = {"/v1/messages": "messages", "/v1/responses": "responses"}.get(request.path, "chat")
    g.context_canary_scope = {"route": request.path, "key_scope": key_scope, "protocol": protocol}
    return None


def register_context_canary(app):
    from services.gateway_extensions import register_authenticated_hook
    register_authenticated_hook(app, context_canary_request_hook)
