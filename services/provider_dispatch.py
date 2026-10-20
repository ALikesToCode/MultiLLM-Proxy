"""The sole provider network boundary, including deferred and non-chat work.

Only an account reference crosses a thread boundary. Its policy is reread at each
submission; a cached principal, environment administrator or old RPC cannot grant
generation authority. Private service bindings receive the same verified reference.
"""

import json
from contextvars import ContextVar
from contextlib import contextmanager
from urllib.parse import parse_qsl, urlsplit

import requests
from flask import current_app, g, has_app_context, has_request_context, request

from error_handlers import APIError
from services.provider_credentials import api_origin, operator_credential, strip_credentials, unavailable_credential
from services.dispatch_network import admitted_network
from services.dispatch_policy import unavailable, verify
from services.key_data_guards import has_data_controls, merge_preferences, model_permitted, preferences

_reference = ContextVar("provider_principal", default=None)


def principal_reference():
    if _reference.get() is not None:
        return _reference.get()
    user = getattr(g, "authenticated_user", None) if has_request_context() else None
    if user:
        return {"username": user.get("username") or user.get("id"), "api_key_prefix": user.get("api_key_prefix")}
    return _reference.get()


@contextmanager
def dispatch_as(reference):
    token = _reference.set(reference)
    try:
        yield
    finally:
        _reference.reset(token)


def current_principal(reference=None):
    from services.auth_service import AuthService
    from services.key_controls import expired

    reference = reference or principal_reference()
    try:
        if not isinstance(reference, dict) or not reference.get("username"):
            raise unavailable()
        if str(reference["username"]).startswith("integration:"):
            from services.intelligence_d1_store import request_private_intelligence
            response = request_private_intelligence({"version": 1, "operation": "dispatch_policy",
                "principalId": reference["username"]}, endpoint="auth")
            if not isinstance(response, dict) or response.get("version") != 1 or set(response) != {"version", "principal"}:
                raise unavailable()
            user = response["principal"]
        else:
            user = AuthService._load_user_by_username(reference["username"])
        if not user or user.get("revoked_at") or expired(user):
            raise unavailable()
        if reference.get("api_key_prefix") and reference["api_key_prefix"] != user.get("api_key_prefix"):
            raise unavailable()
        policy = verify(user.get("data_policy"))
        return {**user, **policy}
    except Exception:
        raise unavailable() from None


def capture_dispatch(callback, *, reference=None):
    """Capture identity and application, never a policy snapshot, for a new thread."""
    reference = reference or principal_reference()
    app = current_app._get_current_object() if has_app_context() else None

    def bound(*args, **kwargs):
        token = _reference.set(reference)
        try:
            if app:
                with app.app_context():
                    return callback(*args, **kwargs)
            return callback(*args, **kwargs)
        finally:
            _reference.reset(token)
    return bound


def _credential(provider, user, url, options, *, public_asset=False):
    headers = dict(options.get("headers") or {})
    if public_asset:
        return {**options, "headers": strip_credentials(headers)}
    if not has_data_controls(user):
        return options
    if any(name.lower() == "key" for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)) or any(
            name.lower() == "key" for name in (options.get("params") or {})):
        raise APIError("Caller provider credentials are not allowed", 403, {"error": "provider_credential_not_allowed"})
    if has_request_context() and (any(name.lower() == "key" for name in request.args)
                                  or "x-goog-api-key" in request.headers):
        raise APIError("Caller provider credentials are not allowed", 403, {"error": "provider_credential_not_allowed"})
    if has_request_context() and request.headers.get("X-MultiLLM-Api-Key"):
        authorization = request.headers.get("Authorization")
        if authorization and (authorization[7:].strip() if authorization.lower().startswith("bearer ") else authorization.strip()) != request.headers["X-MultiLLM-Api-Key"].strip():
            raise APIError("Caller provider credentials are not allowed", 403, {"error": "provider_credential_not_allowed"})
    # A private binding uses the operator's binding rather than a bearer credential.
    if provider == "cloudflare" or urlsplit(url).hostname in {"ai.internal", "knowledge.internal", "media.internal"}:
        return options
    if not api_origin(provider, url):
        raise unavailable_credential()
    # Resolve only after current-policy admission, including OAuth token exchange.
    with admitted_network():
        key = operator_credential(provider)
    headers = strip_credentials(headers)
    header = {"gemini": "x-goog-api-key", "anthropic": "x-api-key", "azure": "api-key"}.get(provider, "Authorization")
    headers[header] = f"Bearer {key}" if header == "Authorization" else key
    return {**options, "headers": headers}


def prepare_dispatch(provider, url, options, *, reference=None, binding=False, public_asset=False):
    user = current_principal(reference)
    if not binding and not model_permitted(user, provider + ":*"):
        raise APIError("This API key cannot use this provider data class", 403, {"error": "provider_class_not_allowed"})
    options = _credential(provider, user, url, dict(options), public_asset=public_asset)
    forced = preferences(user["forced_provider_preferences"])
    if provider == "openrouter" and forced is not None and (options.get("data") is not None or "json" in options):
        try:
            body = options["json"] if "json" in options else json.loads(options["data"])
            if not isinstance(body, dict):
                raise ValueError()
        except (ValueError, TypeError):
            raise APIError("Enforced provider preferences require a JSON object", 400) from None
        body = {**body, "provider": merge_preferences(body.get("provider"), forced)}
        options = {**options, **({"json": body} if "json" in options else {"data": json.dumps(body).encode()})}
    headers = dict(options.get("headers") or {})
    headers = {name: value for name, value in headers.items() if name.lower() not in {"content-length", "x-multillm-dispatch-principal"}}
    if binding:
        headers["X-MultiLLM-Dispatch-Principal"] = json.dumps({"version": 1, "username": user["username"]})
    return {**options, "headers": headers}


def provider_http(provider, method, url, *, transport=None, reference=None, binding=False, public_asset=False, **options):
    options = prepare_dispatch(provider, url, options, reference=reference, binding=binding, public_asset=public_asset)
    # Redirects are separate dispatches and must never forward an attested credential
    # to a provider-selected host without another admission.
    options["allow_redirects"] = False
    with admitted_network():
        return (transport or requests.request)(method=method, url=url, **options)
