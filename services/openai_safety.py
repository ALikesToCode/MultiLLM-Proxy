"""OpenAI end-user attribution and native inline moderation boundaries."""

import hashlib
import hmac

from flask import current_app, g, has_request_context

from error_handlers import APIError
from services.media_catalog import is_moderation_model

_TEXT_ENDPOINTS = frozenset({"v1/chat/completions", "v1/responses"})
_IMAGE_ENDPOINTS = frozenset({"v1/images/generations", "v1/images/edits"})


def principal_safety_identifier():
    """An opaque, deployment-scoped identifier; never an API key or raw username."""
    if not has_request_context():
        return None
    user = getattr(g, "authenticated_user", None)
    if not isinstance(user, dict):
        return None
    principal = user.get("id") if user.get("id") is not None else user.get("username")
    if principal is None:
        return None
    secret = current_app.secret_key
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, f"multillm-safety-v1:{principal}".encode("utf-8"), hashlib.sha256).hexdigest()


def prepare_generation_payload(payload, provider, endpoint, *, native=False):
    """Forward native moderation honestly and add identity only to direct OpenAI."""
    endpoint = endpoint.strip("/")
    if endpoint in _TEXT_ENDPOINTS and not native and is_moderation_model(str(payload.get("model", ""))):
        raise APIError("Moderation models use /v1/moderations", status_code=400)
    if endpoint in _TEXT_ENDPOINTS and "moderation" in payload and not native:
        moderation = payload["moderation"]
        if provider != "openai":
            raise APIError("Inline moderation requires a native OpenAI Chat Completions or Responses route",
                           status_code=400)
        if (not isinstance(moderation, dict) or set(moderation) != {"model"}
                or not isinstance(moderation["model"], str) or not moderation["model"].strip()
                or ":" in moderation["model"]):
            raise APIError("moderation must contain an OpenAI moderation model string", status_code=400)
    if provider != "openai" or endpoint not in _TEXT_ENDPOINTS | _IMAGE_ENDPOINTS:
        return payload
    field = "safety_identifier" if endpoint in _TEXT_ENDPOINTS else "user"
    if field in payload:
        return payload
    identity = principal_safety_identifier()
    return {**payload, field: identity} if identity else payload
