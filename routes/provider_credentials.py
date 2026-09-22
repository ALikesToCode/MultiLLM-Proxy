"""Credential selection and conservative rotation for unified provider routes."""

import requests
from flask import Response

from error_handlers import APIError
from providers.nanogpt import is_nanogpt_paygo_rejection
from routes.auto_routes import AutoRouteCandidateUnavailable
from services.nanogpt_key_pool import (
    NanoGPTKeyPoolExhausted,
    is_nanogpt_credential_rejection,
)
from services.nanogpt_key_pool import NanoGPTUnifiedKeyPool as NanoGPTKeyPool


def _provider_token(app, auth_service_cls, proxy_service_cls, provider: str) -> str:
    if provider == "googleai":
        token = auth_service_cls.get_google_token()
    elif provider == "nanogpt":
        try:
            token = NanoGPTKeyPool.select_key(
                auth_service_cls.get_api_keys("nanogpt"),
                lambda api_key: proxy_service_cls.probe_nanogpt_key(
                    app.config["API_BASE_URLS"]["nanogpt"],
                    api_key,
                    app.config["NANOGPT_KEY_CHECK_TIMEOUT_SECONDS"],
                ),
                check_ttl_seconds=app.config["NANOGPT_KEY_CHECK_TTL_SECONDS"],
                check_every_requests=app.config[
                    "NANOGPT_KEY_CHECK_EVERY_REQUESTS"
                ],
                rejected_cooldown_seconds=app.config[
                    "NANOGPT_KEY_REJECTED_COOLDOWN_SECONDS"
                ],
            )
        except NanoGPTKeyPoolExhausted as error:
            raise AutoRouteCandidateUnavailable(str(error)) from error
    else:
        token = auth_service_cls.get_api_key(provider)
    if not token:
        raise AutoRouteCandidateUnavailable(
            f"API key not configured for {provider}",
        )
    return token


def _is_nanogpt_routing_refusal(response) -> bool:
    """True when NanoGPT refused this request over our own speed suffix."""
    return is_nanogpt_paygo_rejection(
        getattr(response, "status_code", None),
        getattr(response, "content", None),
    )


def _record_nanogpt_token_result(
    app,
    provider: str,
    token: str,
    status_code: int,
    routing_refusal: bool = False,
) -> None:
    if provider != "nanogpt":
        return
    if routing_refusal:
        # The refusal came from our own provider-selection suffix, not from a
        # bad credential. Cooling the key down would strand subscription
        # traffic behind a pool with no usable keys.
        return
    NanoGPTKeyPool.record_result(
        token,
        status_code,
        check_ttl_seconds=app.config["NANOGPT_KEY_CHECK_TTL_SECONDS"],
        rejected_cooldown_seconds=app.config[
            "NANOGPT_KEY_REJECTED_COOLDOWN_SECONDS"
        ],
    )


def _request_with_provider_token_rotation(
    app,
    auth_service_cls,
    proxy_service_cls,
    provider: str,
    send_request,
    billing_refusal_is_routing: bool = False,
):
    """Send once per usable NanoGPT key after definite pre-generation failures."""
    attempt_limit = 1
    if provider == "nanogpt":
        attempt_limit = max(1, len(auth_service_cls.get_api_keys(provider)))

    attempted_tokens: set[str] = set()
    response = None
    attempts = 0
    for _ in range(attempt_limit):
        try:
            token = _provider_token(
                app,
                auth_service_cls,
                proxy_service_cls,
                provider,
            )
        except APIError:
            if response is not None:
                break
            raise

        if token in attempted_tokens:
            break
        attempted_tokens.add(token)
        if response is not None and (
            not isinstance(response, requests.Response) or response.raw is not None
        ):
            response.close()

        response = send_request(token)
        attempts += 1
        routing_refusal = billing_refusal_is_routing and _is_nanogpt_routing_refusal(
            response
        )
        _record_nanogpt_token_result(
            app,
            provider,
            token,
            response.status_code,
            routing_refusal,
        )
        if routing_refusal:
            # Every key would refuse this suffix identically, so rotating on
            # would only surface an unrelated key's error to the caller.
            break
        if provider != "nanogpt" or not is_nanogpt_credential_rejection(
            response.status_code
        ):
            break

    if response is None:
        raise APIError(f"API key not configured for {provider}", status_code=503)
    return response, attempts


def _add_credential_attempt_headers(
    response: Response,
    provider: str,
    attempts: int,
) -> Response:
    if provider == "nanogpt":
        response.headers["X-MultiLLM-Credential-Attempts"] = str(attempts)
    return response
