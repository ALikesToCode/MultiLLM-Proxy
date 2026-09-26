import json
import logging
import time
from collections.abc import Mapping

from flask import Response, jsonify, request

from error_handlers import APIError
from providers.aihubmix import build_aihubmix_image_request
from providers.gpt_image_moderation import apply_gpt_image_moderation_default
from providers.nanogpt import (
    apply_nanogpt_speed_routing,
    nanogpt_model_has_speed_suffix,
    nanogpt_speed_routing,
    strip_nanogpt_speed_suffix,
    nanogpt_subscription_only,
    sanitize_nanogpt_subscription_headers,
    sanitize_nanogpt_subscription_payload,
)
from providers.opencode_go import build_opencode_model_url
from providers.protocols import (
    MESSAGES as MESSAGES_ENDPOINT,
    RESPONSES as RESPONSES_ENDPOINT,
    chat_bridge_endpoint,
    speaks,
)
from providers.registry import get_adapter
from request_validation import json_object_body
from route_helpers import (
    api_auth_required,
    copy_raw_provider_response_headers,
    login_required,
    stream_upstream_response,
)
from routes.auto_routes import (
    dispatch_auto_route,
    dispatch_auto_route_chat_completion,
    mark_transport_failure,
    register_auto_route_admin_routes,
)
from routes.chat_cache import cached_chat_completion
from routes.free_routes import dispatch_free_chat
from routes.model_discovery import register_model_discovery_route
from routes.intelligence import dispatch_intelligence_chat, register_intelligence_routes
from routes.protocol_bridge import (
    ENDPOINT_PROTOCOLS,
    translate_downstream_response,
    translation_api_error,
    translation_request_headers,
)
from routes.unified_messages import register_unified_messages_routes
from routes.media_images import dispatch_auto_image_generation
from routes.unified_transport import (
    normalized_aihubmix_image_response,
    send_configured_unified_provider_request,
    send_unified_image_request,
)
from services.nanogpt_speed_breaker import NanoGPTSpeedBreaker
from services.adaptive_context_service import apply_adaptive_glm_context
from services import cloudflare_ai
from services.media_catalog import (
    TRANSPORT_FAILURE_HEADER,
    image_profile,
    is_video_model,
)
from services.auth_service import AuthService
from services.auto_route_service import AutoRouteService
from services.context_optimizer import ContextOptimizationResult
from services.model_registry import ModelRegistry
from routes.provider_credentials import (
    NanoGPTKeyPool,
    _provider_token,
    _is_nanogpt_routing_refusal,
    _request_with_provider_token_rotation,
    _add_credential_attempt_headers,
)
from services.protocol_translation import (
    CHAT,
    TranslationError,
    strip_unsigned_thinking,
    translate_request,
)
from services.provider_prompt_cache import (
    PromptCacheDecision,
    apply_prompt_cache_policy,
)
from services.rate_limit_service import RateLimitService
from services.reasoning_policy import apply_glm_5_reasoning_policy
from services.transport_policy import RAW_PASSTHROUGH_PROVIDERS

logger = logging.getLogger(__name__)


RAW_CHAT_PASSTHROUGH_PROVIDERS = RAW_PASSTHROUGH_PROVIDERS


def _resolve_enabled_model(app, model_id: str):
    provider, provider_model = ModelRegistry.parse_model_id(model_id)
    adapter = get_adapter(provider, app.config["API_BASE_URLS"])
    if not adapter:
        raise APIError(f"Unsupported provider: {provider}", status_code=400)

    if ModelRegistry.get_model_status(model_id) == "disabled":
        raise APIError(f"Model is disabled: {model_id}", status_code=400)
    return provider, provider_model, adapter


def _copy_request_payload(payload: dict, provider_model: str) -> dict:
    upstream_payload = dict(payload)
    upstream_payload["model"] = provider_model
    return upstream_payload


def _apply_nanogpt_speed_routing(app, provider: str, payload: dict, headers) -> dict:
    """Opt NanoGPT text requests into the configured fast-provider route."""
    if provider != "nanogpt":
        return payload
    suffix = (
        nanogpt_speed_routing(app.config) if NanoGPTSpeedBreaker.allows_suffix() else ""
    )
    return apply_nanogpt_speed_routing(payload, suffix, headers)


def _nanogpt_paygo_downgrade(app, provider: str, response, routed_payload: dict):
    """Return the un-suffixed payload when NanoGPT refused to bill the suffix."""
    if provider != "nanogpt":
        return None
    model = routed_payload.get("model")
    if not nanogpt_model_has_speed_suffix(model):
        return None
    if not _is_nanogpt_routing_refusal(response):
        return None
    NanoGPTSpeedBreaker.record_paygo_rejection(
        app.config["NANOGPT_SPEED_ROUTING_COOLDOWN_SECONDS"]
    )
    logger.warning(
        "NanoGPT rejected provider selection for lack of balance; "
        "retrying %s without the speed suffix and pausing it",
        model,
    )
    return {**routed_payload, "model": strip_nanogpt_speed_suffix(model)}


def _provider_model_url(
    app,
    provider: str,
    provider_model: str,
    upstream_path: str,
    default_url: str,
) -> str:
    if provider != "opencode":
        return default_url
    return build_opencode_model_url(
        app.config["API_BASE_URLS"][provider],
        app.config["OPENCODE_ZEN_BASE_URL"],
        provider_model,
        upstream_path,
    )


def serialize_unified_chat_payload(payload: dict) -> bytes:
    """Serialize the exact Chat Completions body used for limits and dispatch."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _add_adaptive_context_headers(
    response: Response,
    result: ContextOptimizationResult | None,
) -> Response:
    if result is None:
        return response
    response.headers["X-MultiLLM-Optimization"] = result.status
    response.headers["X-MultiLLM-Optimization-Mode"] = "adaptive-deterministic"
    response.headers["X-MultiLLM-Estimated-Input-Before"] = str(
        result.estimated_input_before
    )
    response.headers["X-MultiLLM-Estimated-Input-After"] = str(
        result.estimated_input_after
    )
    response.headers["X-MultiLLM-Image-Prompts-Compacted"] = str(
        result.image_prompts_compacted
    )
    response.headers["X-MultiLLM-Messages-Summarized"] = "0"
    response.headers["X-MultiLLM-Optimization-Target-Met"] = (
        "true" if result.target_met else "false"
    )
    response.headers["X-MultiLLM-Summary"] = "not-requested"
    response.headers["X-MultiLLM-Optimization-Cache-Hits"] = str(
        result.analysis_cache_hits
    )
    response.headers["X-MultiLLM-Optimization-Cache-Misses"] = str(
        result.analysis_cache_misses
    )
    return response


def _add_prompt_cache_headers(
    response: Response,
    decision: PromptCacheDecision,
) -> Response:
    response.headers["X-MultiLLM-Prompt-Cache"] = decision.status
    response.headers["X-MultiLLM-Prompt-Cache-Mode"] = decision.mode
    response.headers["X-MultiLLM-Prompt-Cache-Estimated-Tokens"] = str(
        decision.estimated_input_tokens
    )
    return response


def _merge_request_headers(headers: dict, additions: Mapping[str, str]) -> None:
    existing = {name.lower() for name in headers}
    for name, value in additions.items():
        if name.lower() not in existing:
            headers[name] = value


def _validate_direct_image_target(
    app,
    auth_service_cls,
    proxy_service_cls,
    model_id: str,
) -> str:
    provider, _, adapter = _resolve_enabled_model(app, model_id)
    if not adapter.capabilities().supports_images:
        raise APIError(
            f"Image generation is not supported for provider: {provider}",
            status_code=400,
        )
    _provider_token(app, auth_service_cls, proxy_service_cls, provider)
    return provider


def _validate_direct_chat_target(
    app,
    auth_service_cls,
    proxy_service_cls,
    model_id: str,
) -> str:
    provider, _, _ = _resolve_enabled_model(app, model_id)
    _provider_token(app, auth_service_cls, proxy_service_cls, provider)
    return provider


def validate_unified_chat_target(
    app,
    auth_service_cls,
    model_id: str,
    proxy_service_cls=None,
) -> str:
    """Validate model availability and credentials without dispatching upstream."""
    if proxy_service_cls is None:
        from services.proxy_service import ProxyService

        proxy_service_cls = ProxyService

    if not AutoRouteService.is_auto_route(model_id):
        return _validate_direct_chat_target(
            app,
            auth_service_cls,
            proxy_service_cls,
            model_id,
        )

    route = AutoRouteService.get_route(model_id)
    if route is None:
        raise APIError(f"Auto route not found: {model_id}", status_code=404)
    for candidate in route.candidates:
        try:
            _validate_direct_chat_target(
                app,
                auth_service_cls,
                proxy_service_cls,
                candidate,
            )
            return "auto"
        except (APIError, ValueError):
            continue
    raise APIError(
        f"No configured provider is available for auto route: {route.id}",
        status_code=503,
    )


def _send_native_request(
    app,
    auth_service_cls,
    proxy_service_cls,
    *,
    provider: str,
    provider_model: str,
    endpoint: str,
    body: dict,
    headers_source,
    args_source,
    cache_headers: Mapping[str, str],
    request_timeout=None,
):
    """Send one body to a provider's native Responses or Messages endpoint."""
    raw_body = json.dumps(body).encode("utf-8")

    def send_request(token: str):
        headers = proxy_service_cls.prepare_headers(
            headers_source,
            provider,
            token,
            upstream_path=endpoint,
        )
        _merge_request_headers(headers, cache_headers)
        default_url = f"{app.config['API_BASE_URLS'][provider].rstrip('/')}/{endpoint}"
        request_kwargs = {
            "method": "POST",
            "url": _provider_model_url(app, provider, provider_model, endpoint, default_url),
            "headers": headers,
            "params": proxy_service_cls.prepare_params(
                args_source,
                provider,
                token,
                upstream_path=endpoint,
            ),
            "data": raw_body,
            "api_provider": provider,
            "use_cache": False,
        }
        if body.get("stream"):
            # The managed transport rewrites streams as Chat Completions chunks;
            # only the raw transport keeps a native event stream intact.
            request_kwargs["force_raw_passthrough"] = True
        if request_timeout is not None:
            request_kwargs["timeout_override"] = request_timeout
        return proxy_service_cls.make_request(**request_kwargs)

    return _request_with_provider_token_rotation(
        app,
        auth_service_cls,
        proxy_service_cls,
        provider,
        send_request,
    )


def _dispatch_bridged_chat(
    app,
    auth_service_cls,
    metrics_service_cls,
    proxy_service_cls,
    payload: dict,
    *,
    provider: str,
    provider_model: str,
    endpoint: str,
    headers_source,
    args_source,
    request_timeout,
    start_time: float,
    metrics_model,
    route_decision,
):
    """Serve Chat Completions from a model that speaks only Responses or Messages."""
    target = ENDPOINT_PROTOCOLS[endpoint]
    try:
        body = translate_request(_copy_request_payload(payload, provider_model), CHAT, target)
    except TranslationError as error:
        raise translation_api_error(error) from error
    cache_decision = apply_prompt_cache_policy(
        body,
        provider=provider,
        model=provider_model,
        endpoint=target,
        request_headers=headers_source,
        enabled=app.config["PROMPT_CACHE_ENABLED"],
        minimum_tokens=app.config["PROMPT_CACHE_MIN_TOKENS"],
    )
    response, credential_attempts = _send_native_request(
        app,
        auth_service_cls,
        proxy_service_cls,
        provider=provider,
        provider_model=provider_model,
        endpoint=endpoint,
        body=cache_decision.payload,
        headers_source=headers_source,
        args_source=args_source,
        cache_headers=cache_decision.request_headers,
        request_timeout=request_timeout,
    )
    metrics_service_cls.get_instance().track_request(
        provider=provider,
        status_code=response.status_code,
        response_time=(time.time() - start_time) * 1000,
        model=metrics_model,
        route_decision=route_decision,
    )
    downstream = translate_downstream_response(
        response,
        source=target,
        target=CHAT,
        stream=bool(payload.get("stream")),
    )
    return _add_credential_attempt_headers(
        _add_prompt_cache_headers(downstream, cache_decision),
        provider,
        credential_attempts,
    )


def _dispatch_unified_chat_candidate(
    app,
    auth_service_cls,
    metrics_service_cls,
    proxy_service_cls,
    payload: dict,
    *,
    request_headers=None,
    request_args=None,
    request_timeout=None,
    metrics_model=None,
    route_decision=None,
    adaptive_context=True,
):
    """Dispatch one explicit provider:model Chat Completions candidate."""
    start_time = time.time()
    provider = "unknown"
    headers_source = request.headers if request_headers is None else request_headers
    args_source = request.args if request_args is None else request_args
    try:
        provider, provider_model, adapter = _resolve_enabled_model(
            app,
            payload.get("model"),
        )
        bridge_endpoint = chat_bridge_endpoint(provider, provider_model)
        if bridge_endpoint is not None:
            return _dispatch_bridged_chat(
                app,
                auth_service_cls,
                metrics_service_cls,
                proxy_service_cls,
                payload,
                provider=provider,
                provider_model=provider_model,
                endpoint=bridge_endpoint,
                headers_source=headers_source,
                args_source=args_source,
                request_timeout=request_timeout,
                start_time=start_time,
                metrics_model=metrics_model,
                route_decision=route_decision,
            )
        candidate_payload = _copy_request_payload(payload, provider_model)
        subscription_only = provider == "nanogpt" and nanogpt_subscription_only(
            app.config
        )
        if subscription_only:
            candidate_payload = sanitize_nanogpt_subscription_payload(
                candidate_payload
            )
            headers_source = sanitize_nanogpt_subscription_headers(headers_source)
        adaptive_result = None
        if adaptive_context:
            prompt_limit = RateLimitService._provider_limit(
                provider,
                "MAX_PROMPT_TOKENS",
                128_000,
            )
            adaptive_result = apply_adaptive_glm_context(
                candidate_payload,
                model=provider_model,
                default_target_tokens=max(64, prompt_limit * 3 // 4),
            )
            if adaptive_result is not None:
                candidate_payload = adaptive_result.payload
        upstream_payload = apply_glm_5_reasoning_policy(
            candidate_payload,
            provider,
            provider_model,
        )
        upstream_payload = _apply_nanogpt_speed_routing(
            app, provider, upstream_payload, headers_source
        )
        cache_decision = apply_prompt_cache_policy(
            upstream_payload,
            provider=provider,
            model=provider_model,
            endpoint="chat",
            request_headers=headers_source,
            enabled=app.config["PROMPT_CACHE_ENABLED"],
            minimum_tokens=app.config["PROMPT_CACHE_MIN_TOKENS"],
            nanogpt_subscription_only=subscription_only,
        )
        upstream_payload = cache_decision.payload
        upstream_path = "v1/chat/completions"

        def _encode(body_payload: dict) -> bytes:
            serialized = serialize_unified_chat_payload(body_payload)
            return (
                serialized
                if provider in RAW_CHAT_PASSTHROUGH_PROVIDERS
                else proxy_service_cls.filter_request_data(provider, serialized)
            )

        # Held in a cell so a NanoGPT pay-as-you-go refusal can resend an
        # un-suffixed body through the same rotation.
        outbound = {"data": _encode(upstream_payload)}

        def send_request(token: str):
            headers = proxy_service_cls.prepare_headers(
                headers_source,
                provider,
                token,
                upstream_path=upstream_path,
            )
            _merge_request_headers(headers, cache_decision.request_headers)
            params = (
                proxy_service_cls.prepare_params(
                    args_source,
                    provider,
                    token,
                    upstream_path=upstream_path,
                )
                if provider in RAW_CHAT_PASSTHROUGH_PROVIDERS
                else args_source
            )
            request_kwargs = {
                "method": "POST",
                "url": _provider_model_url(
                    app,
                    provider,
                    provider_model,
                    upstream_path,
                    adapter.chat_completions_url(),
                ),
                "headers": headers,
                "params": params,
                "data": outbound["data"],
                "api_provider": provider,
                "use_cache": False,
            }
            if request_timeout is not None:
                request_kwargs["timeout_override"] = request_timeout
            return send_configured_unified_provider_request(
                proxy_service_cls,
                request_kwargs,
                provider=provider,
                runtime_config=app.config,
                upstream_path=upstream_path,
                request_headers=headers_source,
            )

        response, credential_attempts = _request_with_provider_token_rotation(
            app,
            auth_service_cls,
            proxy_service_cls,
            provider,
            send_request,
            billing_refusal_is_routing=nanogpt_model_has_speed_suffix(
                upstream_payload.get("model")
            ),
        )
        downgraded = _nanogpt_paygo_downgrade(app, provider, response, upstream_payload)
        if downgraded is not None:
            upstream_payload = downgraded
            outbound["data"] = _encode(upstream_payload)
            response, retry_attempts = _request_with_provider_token_rotation(
                app,
                auth_service_cls,
                proxy_service_cls,
                provider,
                send_request,
            )
            credential_attempts += retry_attempts

        metrics_service_cls.get_instance().track_request(
            provider=provider,
            status_code=response.status_code,
            response_time=(time.time() - start_time) * 1000,
            model=metrics_model,
            route_decision=route_decision,
        )

        if isinstance(response, Response):
            return _add_credential_attempt_headers(
                _add_prompt_cache_headers(
                    _add_adaptive_context_headers(response, adaptive_result),
                    cache_decision,
                ),
                provider,
                credential_attempts,
            )
        if provider in RAW_CHAT_PASSTHROUGH_PROVIDERS or payload.get("stream"):
            downstream_response = stream_upstream_response(response)
        else:
            downstream_response = Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get("content-type", "application/json"),
                headers=copy_raw_provider_response_headers(response.headers),
            )
        mark_transport_failure(downstream_response, response)
        return _add_credential_attempt_headers(
            _add_prompt_cache_headers(
                _add_adaptive_context_headers(
                    downstream_response,
                    adaptive_result,
                ),
                cache_decision,
            ),
            provider,
            credential_attempts,
        )
    except ValueError as error:
        raise APIError(str(error), status_code=400) from error
    except Exception as error:
        status_code = error.status_code if isinstance(error, APIError) else 502
        metrics_service_cls.get_instance().track_request(
            provider=provider,
            status_code=status_code,
            response_time=(time.time() - start_time) * 1000,
            model=metrics_model,
            route_decision=route_decision,
        )
        raise


def dispatch_unified_chat_completion(
    app,
    auth_service_cls,
    metrics_service_cls,
    proxy_service_cls,
    payload: dict,
    *,
    request_headers=None,
    request_args=None,
    request_timeout=None,
    adaptive_context=True,
):
    """Dispatch an explicit model or a server-owned chat routing alias."""
    model = payload.get("model")
    if model == "auto:intelligence" or "routing" in payload:
        return dispatch_intelligence_chat(
            app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload
        )
    if isinstance(model, str) and model.startswith("free:"):
        return dispatch_free_chat(
            app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload
        )
    if AutoRouteService.is_auto_route(payload.get("model")):
        def validate_candidate(candidate: str) -> None:
            _validate_direct_chat_target(
                app,
                auth_service_cls,
                proxy_service_cls,
                candidate,
            )

        def dispatch_candidate(
            candidate_payload: dict,
            candidate: str,
            route_decision: str,
        ) -> Response:
            return _dispatch_unified_chat_candidate(
                app,
                auth_service_cls,
                metrics_service_cls,
                proxy_service_cls,
                candidate_payload,
                request_headers=request_headers,
                request_args=request_args,
                request_timeout=request_timeout,
                metrics_model=candidate,
                route_decision=route_decision,
                adaptive_context=adaptive_context,
            )

        return dispatch_auto_route_chat_completion(
            payload,
            validate_candidate=validate_candidate,
            dispatch_candidate=dispatch_candidate,
        )
    return _dispatch_unified_chat_candidate(
        app,
        auth_service_cls,
        metrics_service_cls,
        proxy_service_cls,
        payload,
        request_headers=request_headers,
        request_args=request_args,
        request_timeout=request_timeout,
        adaptive_context=adaptive_context,
    )


def _is_routed_chat_model(payload: dict) -> bool:
    """Server-owned aliases always run through the Chat Completions dispatcher."""
    model = payload.get("model")
    return (
        model == "auto:intelligence"
        or "routing" in payload
        or (isinstance(model, str) and model.startswith("free:"))
        or AutoRouteService.is_auto_route(model)
    )


def _reject_media_only_route(model) -> None:
    route = AutoRouteService.get_route(model) if AutoRouteService.is_auto_route(model) else None
    if route is None or not route.candidates:
        return
    for candidate in route.candidates:
        provider, provider_model = ModelRegistry.parse_model_id(candidate)
        if image_profile(provider, provider_model) is None and not is_video_model(provider_model):
            return
    raise APIError(
        f"{route.id} generates images or video; use /v1/images/generations",
        status_code=400,
    )


def _dispatch_native_protocol(
    app,
    auth_service_cls,
    metrics_service_cls,
    proxy_service_cls,
    payload: dict,
    *,
    provider: str,
    provider_model: str,
    endpoint: str,
):
    """Pass a Responses or Messages body to a provider that speaks it natively."""
    start_time = time.time()
    headers_source = request.headers
    upstream_payload = _copy_request_payload(payload, provider_model)
    if endpoint == RESPONSES_ENDPOINT:
        upstream_payload = apply_glm_5_reasoning_policy(
            upstream_payload,
            provider,
            provider_model,
        )
    else:
        upstream_payload = strip_unsigned_thinking(upstream_payload)
    upstream_payload = _apply_nanogpt_speed_routing(
        app, provider, upstream_payload, headers_source
    )
    cache_decision = apply_prompt_cache_policy(
        upstream_payload,
        provider=provider,
        model=provider_model,
        endpoint=ENDPOINT_PROTOCOLS[endpoint],
        request_headers=headers_source,
        enabled=app.config["PROMPT_CACHE_ENABLED"],
        minimum_tokens=app.config["PROMPT_CACHE_MIN_TOKENS"],
    )
    response, credential_attempts = _send_native_request(
        app,
        auth_service_cls,
        proxy_service_cls,
        provider=provider,
        provider_model=provider_model,
        endpoint=endpoint,
        body=cache_decision.payload,
        headers_source=headers_source,
        args_source=request.args,
        cache_headers=cache_decision.request_headers,
    )
    metrics_service_cls.get_instance().track_request(
        provider=provider,
        status_code=response.status_code,
        response_time=(time.time() - start_time) * 1000,
    )
    downstream_response = (
        response if isinstance(response, Response) else stream_upstream_response(response)
    )
    return _add_credential_attempt_headers(
        _add_prompt_cache_headers(downstream_response, cache_decision),
        provider,
        credential_attempts,
    )


def _dispatch_translated_protocol(
    app,
    auth_service_cls,
    metrics_service_cls,
    proxy_service_cls,
    payload: dict,
    protocol: str,
):
    """Serve a Responses or Messages request through the Chat Completions dispatcher."""
    try:
        chat_payload = translate_request(payload, protocol, CHAT)
    except TranslationError as error:
        raise translation_api_error(error) from error
    if "routing" in payload:
        chat_payload["routing"] = payload["routing"]
    response = dispatch_unified_chat_completion(
        app,
        auth_service_cls,
        metrics_service_cls,
        proxy_service_cls,
        chat_payload,
        request_headers=translation_request_headers(request.headers),
    )
    return translate_downstream_response(
        response,
        source=CHAT,
        target=protocol,
        stream=bool(chat_payload.get("stream")),
        model=payload.get("model"),
        request_payload=payload,
    )


def dispatch_protocol_request(
    app,
    auth_service_cls,
    metrics_service_cls,
    proxy_service_cls,
    payload: dict,
    endpoint: str,
):
    """Dispatch a Responses or Messages request: native when the model speaks it,
    translated through Chat Completions otherwise (automatic routes included)."""
    protocol = ENDPOINT_PROTOCOLS[endpoint]
    if _is_routed_chat_model(payload):
        _reject_media_only_route(payload.get("model"))
        return _dispatch_translated_protocol(
            app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload, protocol
        )
    start_time = time.time()
    provider = "unknown"
    try:
        provider, provider_model, _ = _resolve_enabled_model(app, payload.get("model"))
        if endpoint == RESPONSES_ENDPOINT and provider == "kimi-code":
            raise APIError(
                "Kimi Code does not support the Responses API; use /v1/chat/completions",
                status_code=400,
            )
        subscription_only = provider == "nanogpt" and nanogpt_subscription_only(
            app.config
        )
        if speaks(provider, provider_model, endpoint) and not subscription_only:
            return _dispatch_native_protocol(
                app,
                auth_service_cls,
                metrics_service_cls,
                proxy_service_cls,
                payload,
                provider=provider,
                provider_model=provider_model,
                endpoint=endpoint,
            )
    except ValueError as error:
        raise APIError(str(error), status_code=400) from error
    except Exception as error:
        status_code = error.status_code if isinstance(error, APIError) else 502
        metrics_service_cls.get_instance().track_request(
            provider=provider,
            status_code=status_code,
            response_time=(time.time() - start_time) * 1000,
        )
        raise
    return _dispatch_translated_protocol(
        app, auth_service_cls, metrics_service_cls, proxy_service_cls, payload, protocol
    )


def _validate_image_candidate(app, auth_service_cls, proxy_service_cls, model_id: str) -> None:
    provider, _ = ModelRegistry.parse_model_id(model_id)
    if provider == "cloudflare":
        if not cloudflare_ai.enabled():
            raise APIError("Cloudflare AI is not bound to this deployment", status_code=503)
        return
    _validate_direct_image_target(app, auth_service_cls, proxy_service_cls, model_id)


def dispatch_unified_image_generation(
    app,
    auth_service_cls,
    metrics_service_cls,
    proxy_service_cls,
    payload: dict,
    *,
    request_headers=None,
    request_args=None,
):
    """Dispatch an OpenAI Images request, translating provider-native models."""
    if AutoRouteService.is_auto_route(payload.get("model")):
        return dispatch_auto_image_generation(
            payload,
            validate_candidate=lambda candidate: _validate_image_candidate(
                app, auth_service_cls, proxy_service_cls, candidate
            ),
            dispatch_candidate=lambda candidate_payload: dispatch_unified_image_generation(
                app,
                auth_service_cls,
                metrics_service_cls,
                proxy_service_cls,
                candidate_payload,
                request_headers=request_headers,
                request_args=request_args,
            ),
        )

    if cloudflare_ai.is_cloudflare_model(payload.get("model")):
        start_time = time.time()
        response = cloudflare_ai.generate_image(payload)
        metrics_service_cls.get_instance().track_request(
            provider="cloudflare",
            status_code=response.status_code,
            response_time=(time.time() - start_time) * 1000,
        )
        return response

    start_time = time.time()
    provider = "unknown"
    headers_source = request.headers if request_headers is None else request_headers
    args_source = request.args if request_args is None else request_args
    try:
        provider, provider_model, adapter = _resolve_enabled_model(
            app,
            payload.get("model"),
        )
        if not adapter.capabilities().supports_images:
            raise APIError(
                f"Image generation is not supported for provider: {provider}",
                status_code=400,
            )

        payload, _ = apply_gpt_image_moderation_default(payload, model_id=provider_model)

        response_kind = "openai"
        if provider == "aihubmix":
            image_request = build_aihubmix_image_request(
                provider_model,
                payload,
            )
            upstream_path = image_request.path
            upstream_payload = image_request.payload
            response_kind = image_request.response_kind
        else:
            upstream_path = "v1/images/generations"
            upstream_payload = _copy_request_payload(payload, provider_model)
        raw_body = serialize_unified_chat_payload(upstream_payload)
        operation_base_url = (
            app.config["NANOGPT_STANDARD_BASE_URL"]
            if provider == "nanogpt"
            else app.config["API_BASE_URLS"][provider]
        )

        def send_request(token: str):
            return send_unified_image_request(
                proxy_service_cls,
                provider=provider,
                token=token,
                request_headers=headers_source,
                request_args=args_source,
                upstream_path=upstream_path,
                raw_body=raw_body,
                primary_origin=operation_base_url,
                secondary_origin=(
                    app.config["AIHUBMIX_BACKUP_BASE_URL"]
                    if provider == "aihubmix"
                    else None
                ),
            )

        response, credential_attempts = _request_with_provider_token_rotation(
            app,
            auth_service_cls,
            proxy_service_cls,
            provider,
            send_request,
        )

        metrics_service_cls.get_instance().track_request(
            provider=provider,
            status_code=response.status_code,
            response_time=(time.time() - start_time) * 1000,
        )

        if isinstance(response, Response):
            downstream_response = response
        else:
            downstream_response = (
                normalized_aihubmix_image_response(response, response_kind)
                if provider == "aihubmix"
                else None
            ) or stream_upstream_response(response)
            transport_failure = getattr(response, "multillm_transport_failure", None)
            if transport_failure:
                downstream_response.headers[TRANSPORT_FAILURE_HEADER] = transport_failure
        return _add_credential_attempt_headers(
            downstream_response,
            provider,
            credential_attempts,
        )
    except ValueError as error:
        raise APIError(str(error), status_code=400) from error
    except Exception as error:
        status_code = error.status_code if isinstance(error, APIError) else 502
        metrics_service_cls.get_instance().track_request(
            provider=provider,
            status_code=status_code,
            response_time=(time.time() - start_time) * 1000,
        )
        raise


def register_unified_routes(app, csrf, auth_service_cls, metrics_service_cls, proxy_service_cls) -> None:
    register_intelligence_routes(app, csrf, auth_service_cls, metrics_service_cls, proxy_service_cls)
    register_model_discovery_route(app, csrf, auth_service_cls, proxy_service_cls)
    register_auto_route_admin_routes(
        app,
        login_required,
        auth_service_cls,
        proxy_service_cls,
    )

    @app.route("/admin/models/<path:model_id>/disable", methods=["POST"])
    @login_required
    def disable_admin_model(model_id: str):
        current_user = AuthService.get_current_user()
        if not current_user or not current_user.get("is_admin"):
            raise APIError("Only admin users can disable models", status_code=403)
        try:
            ModelRegistry.parse_model_id(model_id)
        except ValueError as error:
            raise APIError(str(error), status_code=400) from error
        if not ModelRegistry.get_model(model_id, app.config["API_BASE_URLS"]):
            raise APIError(f"Model not found: {model_id}", status_code=404)
        ModelRegistry.disable_model(model_id)
        return jsonify({"model": model_id, "status": "disabled"})

    @app.route("/v1/chat/completions", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    @cached_chat_completion
    def unified_chat_completions():
        payload = json_object_body()
        return dispatch_unified_chat_completion(
            app,
            auth_service_cls,
            metrics_service_cls,
            proxy_service_cls,
            payload,
        )

    @app.route("/v1/images/generations", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def unified_image_generations():
        payload = json_object_body()
        return dispatch_unified_image_generation(
            app,
            auth_service_cls,
            metrics_service_cls,
            proxy_service_cls,
            payload,
        )

    @app.route("/v1/responses", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def unified_responses():
        return dispatch_protocol_request(
            app,
            auth_service_cls,
            metrics_service_cls,
            proxy_service_cls,
            json_object_body(),
            RESPONSES_ENDPOINT,
        )

    register_unified_messages_routes(
        app,
        csrf,
        lambda payload: dispatch_protocol_request(
            app,
            auth_service_cls,
            metrics_service_cls,
            proxy_service_cls,
            payload,
            MESSAGES_ENDPOINT,
        ),
    )
