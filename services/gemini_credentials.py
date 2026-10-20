"""Credential selection for native and translated Gemini requests."""

import logging
import os
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import g, has_request_context, request

from error_handlers import APIError
from services.auth_primitives import usable_credential

logger = logging.getLogger(__name__)


def restricted(provider):
    return provider == "gemini" and has_request_context() and bool(
        (getattr(g, "authenticated_user", None) or {}).get("official_only"))


def _refuse_override():
    raise APIError("Caller provider credentials are not allowed for this key", 403,
                   {"error": "provider_credential_not_allowed"})


def reject_caller_credentials(provider):
    if not restricted(provider):
        return
    if any(name.lower() == "key" for name in request.args) or "x-goog-api-key" in request.headers:
        _refuse_override()
    gateway = request.headers.get("x-multillm-api-key")
    authorization = request.headers.get("authorization")
    if gateway and authorization:
        bearer = re.fullmatch(r"Bearer\s+(.+)", authorization.strip(), re.IGNORECASE)
        if not bearer or bearer[1].strip() != gateway.strip():
            _refuse_override()


def prepare_credentials(url, headers, params, provider, auth_token, auth):
    headers, params = dict(headers or {}), dict(params or {})
    if restricted(provider):
        reject_caller_credentials(provider)
        if any(name.lower() == "key" for name in params) or any(
                name.lower() == "key" for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)):
            _refuse_override()
        # Only this operator binding is covered by the paid-tier attestation. Do not
        # recover through a legacy alias, cached credential or caller-supplied key.
        key = usable_credential(os.environ.get("GEMINI_API_KEY"), "GEMINI_API_KEY")
        if not key:
            raise APIError("Attested provider credential is unavailable", 503,
                           {"error": "attested_credential_unavailable"})
        gateway_authorization = request.headers.get("authorization")
        for name, value in headers.items():
            if name.lower() == "x-goog-api-key" and value != key:
                _refuse_override()
            if name.lower() == "authorization" and value not in {f"Bearer {key}", gateway_authorization}:
                _refuse_override()
    else:
        url, params, key = _legacy_credentials(url, params, provider, auth_token, auth)
    headers = {name: value for name, value in headers.items()
               if name.lower() not in {"authorization", "x-goog-api-key"}}
    headers["x-goog-api-key"] = key
    return url, headers, params


def _legacy_credentials(url, params, api_provider, auth_token, auth):
    # Extract API key from URL parameters and rebuild the URL without it
    api_key = None

    # Check if key is in params
    if params and 'key' in params:
        api_key = params.pop('key')
        if isinstance(api_key, (list, tuple)):
            api_key = api_key[0] if api_key else None
        logger.info(f"Found API key in URL parameters for {api_provider}")

    # If no key in params, check if it's in the URL
    else:
        parsed_url = urlsplit(url)
        query_pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
        filtered_query_pairs = []
        for key, value in query_pairs:
            if key == 'key' and api_key is None:
                api_key = value
                logger.info(f"Found API key in URL for {api_provider}")
            else:
                filtered_query_pairs.append((key, value))

        if api_key is not None:
            url = urlunsplit(
                (
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    urlencode(filtered_query_pairs),
                    parsed_url.fragment,
                )
            )

    # If still no API key, use the auth token passed from make_request
    # But first check if it's the admin API key - if so, use the Gemini key from env instead
    if not api_key and auth_token:
        admin_api_key = os.environ.get('ADMIN_API_KEY')
        if auth_token == admin_api_key:
            # Using admin key, look up the actual provider key instead
            logger.info(f"Admin API key detected - using {api_provider} API key from env instead")
            api_key = auth.get_api_key(api_provider)
            if not api_key:
                # Try alternative keys
                if api_provider == 'gemma':
                    api_key = auth.get_api_key('gemini')
                elif api_provider == 'gemini':
                    api_key = auth.get_api_key('gemma')
        else:
            # Not the admin key, might be a direct Gemini key
            api_key = auth_token
            logger.info(f"Using API key from Authorization header for {api_provider}")

    # If still no API key, get from auth service
    if not api_key:
        # First try with the exact api_provider
        api_key = auth.get_api_key(api_provider)

        # If using 'gemma' as provider but no gemma key found, try with 'gemini' as they share the same key
        if not api_key and api_provider == 'gemma':
            api_key = auth.get_api_key('gemini')
            logger.info("Using Gemini API key for Gemma model")

        # If using 'gemini' as provider but no gemini key found, try with 'gemma' as a fallback
        elif not api_key and api_provider == 'gemini':
            api_key = auth.get_api_key('gemma')
            logger.info("Using Gemma API key for Gemini model")

        if not api_key:
            raise APIError(f"No API key found for {api_provider}. Please set {api_provider.upper()}_API_KEY in your .env file.", status_code=401)

        logger.info(f"Using API key from AuthService for {api_provider}")

    # Validate API key format - Gemini keys should start with "AIza"
    if not api_key.startswith("AIza"):
        logger.warning(f"API key for {api_provider} doesn't match expected format (should start with 'AIza')")
        # Try to find a valid key from the environment
        env_key = os.environ.get(f'{api_provider.upper()}_API_KEY')
        if env_key and env_key.startswith("AIza"):
            logger.info(f"Found valid {api_provider} API key format in environment, using it instead")
            api_key = env_key

    return url, params, api_key
