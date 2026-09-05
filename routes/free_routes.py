"""OpenAI-compatible, free-only pools with bounded account-quota failover."""

import json
import time

import requests
from flask import Response, g, jsonify, request

from error_handlers import APIError
from request_validation import json_object_body
from route_helpers import api_auth_required, stream_upstream_response
from routes.free_response import FreeUpstreamFailure, validated_free_response
from services.free_model_policy import (
    FREE_MODELS,
    free_candidates,
    validate_free_payload,
)
from services.free_quota_service import FreeQuotaService, retry_seconds

# Fixed official origins keep a custom relay from reinterpreting a free model
# as a paid alias. Regular provider routes retain their configurable origins.
FREE_CHAT_URLS = {
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "opencode": "https://opencode.ai/zen/v1/chat/completions",
    "aihubmix": "https://aihubmix.com/v1/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
}
FAILOVER_STATUSES = {401, 402, 403, 404, 429, 500, 502, 503, 504}
MAX_ATTEMPTS = 8
REQUEST_DEADLINE_SECONDS = 120


def _cooldown(candidate) -> int:
    return max(
        FreeQuotaService.remaining(f"provider:{candidate.provider}"),
        FreeQuotaService.remaining(f"model:{candidate.id}"),
    )


def _record_failure(candidate, status, headers) -> None:
    scope = (
        f"model:{candidate.id}" if status == 404 else f"provider:{candidate.provider}"
    )
    default = 300 if status in {401, 402, 403, 404} else 60
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


def _request_candidate(auth, proxy, payload, candidate, remaining):
    token = auth.get_api_key(candidate.provider)
    if not token:
        raise FreeUpstreamFailure(503)
    return proxy.make_request(
        method="POST",
        url=FREE_CHAT_URLS[candidate.provider],
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream"
            if payload.get("stream")
            else "application/json",
        },
        params={},
        data=json.dumps(
            {**payload, "model": candidate.model}, ensure_ascii=False
        ).encode("utf-8"),
        api_provider=candidate.provider,
        use_cache=False,
        timeout_override=(min(5, remaining), min(60, remaining)),
        force_raw_passthrough=True,
    )


def _try_candidate(auth, metrics, proxy, payload, candidate, remaining, deadline):
    start = time.monotonic()
    status = 502
    upstream = None
    headers = {}
    try:
        upstream = _request_candidate(auth, proxy, payload, candidate, remaining)
        status, headers = upstream.status_code, upstream.headers
        if status in FAILOVER_STATUSES:
            raise FreeUpstreamFailure(status)
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
            stream=payload.get("stream", False),
            deadline=deadline,
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
        _record_failure(candidate, status, headers)
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


def _exhausted_response(configured, model, attempts):
    delays = [_cooldown(c) for c in configured]
    cooling = all(delays)
    response = jsonify(
        {
            "error": {
                "code": "free_pool_exhausted" if cooling else "free_attempt_limit",
                "message": "No free provider is currently available. Retry later; no paid model was used.",
            }
        }
    )
    response.status_code = 429 if cooling else 503
    response.headers["Retry-After"] = str(min(delays) if cooling else 1)
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
    configured = [c for c in candidates if auth.get_api_key(c.provider)]
    if not configured:
        return jsonify(
            {
                "error": {
                    "code": "free_models_unavailable",
                    "message": "No configured eligible free models. Configure a provider and refresh the live catalog; "
                    "vision requires confirmed image-input metadata.",
                }
            }
        ), 503
    deadline = time.monotonic() + REQUEST_DEADLINE_SECONDS
    attempts = 0
    for priority, candidate in enumerate(configured, 1):
        if _cooldown(candidate):
            continue
        remaining = int(deadline - time.monotonic())
        if attempts >= MAX_ATTEMPTS or remaining < 2:
            break
        attempts += 1
        response = _try_candidate(
            auth, metrics, proxy, payload, candidate, remaining, deadline
        )
        if response is not None:
            return _decorate(response, candidate, model, attempts, priority)
    return _exhausted_response(configured, model, attempts)


def register_free_routes(app, csrf, auth, metrics, proxy):
    @app.route("/v1/free/models", methods=["GET", "OPTIONS"])
    @app.route("/v1/free/<mode>/models", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_auth_required(required_scope="models")
    def list_free_models(mode=None):
        if mode is not None and f"free:{mode}" not in FREE_MODELS:
            raise APIError("Unknown free route", status_code=404)
        models = []
        for model, vision in FREE_MODELS.items():
            if mode is not None and model != f"free:{mode}":
                continue
            candidates = free_candidates(app.config, vision=vision)
            models.append(
                {
                    "id": model,
                    "object": "model",
                    "created": 0,
                    "owned_by": "multillm",
                    "supports_vision": vision,
                    "candidates": [
                        {
                            "id": c.id,
                            "provider": c.provider,
                            "supports_vision": c.vision,
                            "billing_basis": c.billing_basis,
                            "configured": bool(auth.get_api_key(c.provider)),
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
