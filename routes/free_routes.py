"""OpenAI-compatible, free-only pools with bounded account-quota failover."""

import json
import time

import requests
from flask import Response, g, jsonify, request

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_auth_required, stream_upstream_response
from routes.free_response import FreeUpstreamFailure, validated_free_response
from services.free_json_contract import json_output_requested
from services.free_model_policy import (
    FREE_MODELS,
    free_candidates,
    free_model_aliases,
    validate_free_payload,
)
from services.free_provider_catalog import FREE_PROVIDERS, free_chat_url, provider_setup
from services.free_quota_service import FreeQuotaService, retry_seconds
from services.free_route_diagnostics import exhausted_details, failure_detail

FAILOVER_STATUSES = {401, 402, 403, 404, 410, 429, 500, 502, 503, 504}
MAX_ATTEMPTS = 8
REQUEST_DEADLINE_SECONDS = 120


def _cooldown(candidate) -> int:
    return max(
        FreeQuotaService.remaining(f"provider:{candidate.provider}"),
        FreeQuotaService.remaining(f"model:{candidate.id}"),
    )


def _record_failure(candidate, status, headers) -> None:
    if (
        candidate.provider == "orcarouter"
        and status == 429
        and not any(k.lower() == "retry-after" for k in headers.keys())
    ):
        # OrcaRouter uses this for a prompt-size cap, not exhausted account quota.
        return
    scope = (
        f"model:{candidate.id}"
        if status in {404, 410}
        else f"provider:{candidate.provider}"
    )
    default = 300 if status in {401, 402, 403, 404, 410} else 60
    FreeQuotaService.block(scope, retry_seconds(headers, time.time(), default))


def _decorate(response, candidate, model, attempts, priority):
    g.multillm_provider = candidate.provider
    g.multillm_model = candidate.id
    g.multillm_route_decision = "free-primary" if priority == 1 else "free-failover"
    response.headers["X-MultiLLM-Auto-Route"] = model
    response.headers["X-MultiLLM-Auto-Selected-Model"] = candidate.id
    response.headers["X-MultiLLM-Auto-Attempts"] = str(attempts)
    response.headers["X-MultiLLM-Auto-Selected-Priority"] = str(priority)
    return response


def _close_upstream(upstream):
    if not isinstance(upstream, Response) and upstream.raw is None:
        upstream._content_consumed = True
    upstream.close()


def _request_candidate(config, auth, proxy, payload, candidate, remaining):
    token = auth.get_api_key(candidate.provider)
    url = free_chat_url(config, candidate.provider)
    if not token or not url:
        raise FreeUpstreamFailure(503, reason="credentials_unavailable")
    upstream_payload = {**payload, "model": candidate.model}
    if candidate.provider == "openrouter" and json_output_requested(
        payload.get("response_format")
    ):
        # Unsupported formatting must fail instead of silently becoming plain text.
        upstream_payload["provider"] = {"require_parameters": True}
    return proxy.make_request(
        method="POST",
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream"
            if payload.get("stream")
            else "application/json",
            **dict(FREE_PROVIDERS[candidate.provider].headers),
        },
        params={},
        data=json.dumps(upstream_payload, ensure_ascii=False).encode("utf-8"),
        api_provider=candidate.provider,
        use_cache=False,
        timeout_override=(min(5, remaining), min(60, remaining)),
        force_raw_passthrough=True,
    )


def _record_attempt_failure(candidate, payload, error, status, upstream_status, headers):
    # Parameter-support 404s do not disable ordinary OpenRouter text requests.
    unsupported = (
        status == 404
        and candidate.provider == "openrouter"
        and json_output_requested(payload.get("response_format"))
    )
    if not unsupported:
        _record_failure(candidate, status, headers)
    if unsupported:
        reason = "unsupported_parameters"
    elif isinstance(error, requests.Timeout):
        reason = "timeout"
    elif isinstance(error, requests.RequestException):
        reason = "connection_error"
    elif isinstance(error, FreeUpstreamFailure):
        reason = error.reason
    else:
        reason = None
    return failure_detail(candidate, status, upstream_status, reason, _cooldown(candidate))


def _try_candidate(
    config, auth, metrics, proxy, payload, candidate, remaining, deadline, failures
):
    start = time.monotonic()
    status = 502
    upstream = None
    upstream_status = None
    headers = {}
    try:
        upstream = _request_candidate(
            config, auth, proxy, payload, candidate, remaining
        )
        status, headers = upstream.status_code, upstream.headers
        upstream_status = status
        if status in FAILOVER_STATUSES:
            raise FreeUpstreamFailure(status, reason="upstream_status")
        if status >= 400:
            return (
                upstream
                if isinstance(upstream, Response)
                else stream_upstream_response(upstream)
            )
        if status != 200:
            raise FreeUpstreamFailure()
        FreeQuotaService.observe(candidate.provider, headers)
        return validated_free_response(
            upstream,
            provider=candidate.provider,
            stream=payload.get("stream", False),
            deadline=deadline,
            response_format=payload.get("response_format"),
            on_failure=lambda status: _record_failure(candidate, status, headers),
        )
    except (requests.RequestException, FreeUpstreamFailure, APIError) as error:
        status = (
            error.status_code
            if isinstance(error, APIError)
            else (error.status if isinstance(error, FreeUpstreamFailure) else 502)
        )
        if status not in FAILOVER_STATUSES:
            raise
        failures.append(
            _record_attempt_failure(
                candidate, payload, error, status, upstream_status, headers
            )
        )
        if upstream is not None:
            _close_upstream(upstream)
        return None
    finally:
        metrics.get_instance().track_request(
            provider=candidate.provider,
            status_code=status,
            response_time=(time.monotonic() - start) * 1000,
            model=candidate.id,
            route_decision="free-attempt",
        )


def _exhausted_response(configured, model, attempts, failures, stop_reason):
    status, details = exhausted_details(
        configured, failures, _cooldown, stop_reason=stop_reason
    )
    details["attempts"] = attempts
    response = jsonify({"error": details})
    response.status_code = status
    if details["retry_after"] is not None:
        response.headers["Retry-After"] = str(details["retry_after"])
    response.headers["X-MultiLLM-Auto-Route"] = model
    response.headers["X-MultiLLM-Auto-Attempts"] = str(attempts)
    return response


def dispatch_free_chat(app, auth, metrics, proxy, payload, fixed_model=None):
    payload = validate_free_payload(payload, fixed_model)
    if request.args:
        raise APIError("Free routes do not accept query parameters", status_code=400)
    model = payload["model"]
    candidates = free_candidates(app.config, vision=FREE_MODELS[model])
    # Look up credentials only through the existing server-side store. Caller
    # headers are never forwarded, and keys are never included in pool status.
    configured = [
        c
        for c in candidates
        if auth.get_api_key(c.provider) and free_chat_url(app.config, c.provider)
    ]
    if not configured:
        return jsonify(
            {
                "error": {
                    "code": "free_models_unavailable",
                    "message": "No configured eligible free models. Configure a provider and refresh the live catalog; "
                    "vision requires confirmed image-input metadata.",
                    "reason": "no_eligible_models",
                    "retryable": False,
                    "retry_after": None,
                    "attempts": 0,
                    "failures": [],
                }
            }
        ), 503
    deadline = time.monotonic() + REQUEST_DEADLINE_SECONDS
    attempts = 0
    failures = []
    stop_reason = "providers_failed"
    for priority, candidate in enumerate(configured, 1):
        if _cooldown(candidate):
            continue
        remaining = int(deadline - time.monotonic())
        if attempts >= MAX_ATTEMPTS or remaining < 2:
            stop_reason = (
                "attempt_limit" if attempts >= MAX_ATTEMPTS else "deadline_exceeded"
            )
            break
        attempts += 1
        response = _try_candidate(
            app.config,
            auth,
            metrics,
            proxy,
            payload,
            candidate,
            remaining,
            deadline,
            failures,
        )
        if response is not None:
            return _decorate(response, candidate, model, attempts, priority)
    return _exhausted_response(configured, model, attempts, failures, stop_reason)


def register_free_routes(app, csrf, auth, metrics, proxy):
    @app.route("/v1/free/providers", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_auth_required(required_scope="models")
    def list_free_providers():
        return jsonify({"object": "list", "data": provider_setup(app.config, auth)})

    @app.route("/v1/free/models", methods=["GET", "OPTIONS"])
    @app.route("/v1/free/<mode>/models", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_auth_required(required_scope="models")
    def list_free_models(mode=None):
        if mode is not None and f"free:{mode}" not in FREE_MODELS:
            raise APIError("Unknown free route", status_code=404)
        models = []
        for alias in free_model_aliases():
            if mode is not None and alias["id"] != f"free:{mode}":
                continue
            candidates = free_candidates(app.config, vision=alias["supports_vision"])
            models.append(
                {
                    **alias,
                    "candidates": [
                        {
                            "id": c.id,
                            "provider": c.provider,
                            "supports_vision": c.vision,
                            "billing_basis": c.billing_basis,
                            "configured": bool(
                                auth.get_api_key(c.provider)
                                and free_chat_url(app.config, c.provider)
                            ),
                            "retry_after": _cooldown(c),
                        }
                        for c in candidates
                    ],
                }
            )
        return jsonify({"object": "list", "data": models})

    @app.route("/v1/free/chat/completions", methods=["POST", "OPTIONS"])
    @app.route("/v1/free/<mode>/chat/completions", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def free_chat_completions(mode=None):
        if mode is not None and f"free:{mode}" not in FREE_MODELS:
            raise APIError("Unknown free route", status_code=404)
        return dispatch_free_chat(
            app,
            auth,
            metrics,
            proxy,
            json_object_body(),
            f"free:{mode}" if mode else None,
        )
