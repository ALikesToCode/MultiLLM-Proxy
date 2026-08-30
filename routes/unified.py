import json
import time
from collections.abc import Mapping

import requests
from flask import Response, jsonify, request

from error_handlers import APIError
from providers.aihubmix import build_aihubmix_image_request
from providers.gpt_image_moderation import apply_gpt_image_moderation_default
from providers.nanogpt import (
    nanogpt_subscription_only,
    sanitize_nanogpt_subscription_headers,
    sanitize_nanogpt_subscription_payload,
)
from providers.opencode_go import (
    build_opencode_model_url,
    opencode_model_endpoint,
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
    AutoRouteCandidateUnavailable,
    dispatch_auto_route_chat_completion,
    openai_auto_route_models,
    register_auto_route_admin_routes,
)
from routes.responses_compat import (
    chat_response_to_responses_payload,
    responses_input_to_messages,
)
from routes.unified_transport import (
    normalized_aihubmix_image_response,
    send_configured_unified_provider_request,
    send_unified_image_request,
)
from services.adaptive_context_service import apply_adaptive_glm_context
from services.auth_service import AuthService
from services.auto_route_service import AutoRouteService
from services.context_optimizer import ContextOptimizationResult
from services.model_catalog_service import build_model_catalog, unified_model_payload
from services.model_registry import ModelRegistry
from services.nanogpt_key_pool import (
    NanoGPTKeyPoolExhausted,
    is_nanogpt_credential_rejection,
)
from services.nanogpt_key_pool import NanoGPTUnifiedKeyPool as NanoGPTKeyPool
from services.provider_prompt_cache import (
    PromptCacheDecision,
    apply_prompt_cache_policy,
)
from services.rate_limit_service import RateLimitService
from services.reasoning_policy import apply_glm_5_reasoning_policy
from services.transport_policy import RAW_PASSTHROUGH_PROVIDERS

RAW_CHAT_PASSTHROUGH_PROVIDERS = RAW_PASSTHROUGH_PROVIDERS
NATIVE_RESPONSES_PROVIDERS = frozenset(
    {"codex-easy", "linkapi", "nanogpt", "navyai", "opencode"}
)


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


def _record_nanogpt_token_result(
    app,
    provider: str,
    token: str,
    status_code: int,
) -> None:
    if provider != "nanogpt":
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
        _record_nanogpt_token_result(
            app,
            provider,
            token,
            response.status_code,
        )
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


def _resolve_enabled_model(app, model_id: str):
    provider, provider_model = ModelRegistry.parse_model_id(model_id)
    adapter = get_adapter(provider, app.config["API_BASE_URLS"])
    if not adapter:
        raise APIError(f"Unsupported provider: {provider}", status_code=400)

    if ModelRegistry.get_model_status(model_id) == "disabled":
        raise APIError(f"Model is disabled: {model_id}", status_code=400)
    return provider, provider_model, adapter


def _decode_upstream_json(response: requests.Response) -> dict:
    try:
        payload = response.json()
    except ValueError as error:
        raise APIError("Upstream provider returned a non-JSON response", status_code=502) from error

    if not isinstance(payload, dict):
        raise APIError("Upstream provider returned an unsupported JSON response", status_code=502)
    return payload


def _copy_request_payload(payload: dict, provider_model: str) -> dict:
    upstream_payload = dict(payload)
    upstream_payload["model"] = provider_model
    return upstream_payload


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


def _pass_through_response(response: requests.Response) -> Response:
    return Response(
        response.content,
        status=response.status_code,
        content_type=response.headers.get("content-type", "application/json"),
        headers=copy_raw_provider_response_headers(response.headers),
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
        raw_body = serialize_unified_chat_payload(upstream_payload)
        upstream_path = "v1/chat/completions"
        request_data = (
            raw_body
            if provider in RAW_CHAT_PASSTHROUGH_PROVIDERS
            else proxy_service_cls.filter_request_data(provider, raw_body)
        )

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
                "data": request_data,
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
        )

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
    """Dispatch an explicit or dashboard-configured unified chat model."""
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
    register_auto_route_admin_routes(
        app,
        login_required,
        auth_service_cls,
        proxy_service_cls,
    )

    @app.route("/v1/models", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_auth_required(required_scope="models")
    def list_unified_models():
        models = [
            unified_model_payload(model)
            for model in build_model_catalog(
                app.config["API_BASE_URLS"],
                AutoRouteService.list_routes(),
            )
            if model["status"] != "disabled"
        ]
        models.extend(openai_auto_route_models())
        return jsonify({"object": "list", "data": models})

    @app.route("/admin/models", methods=["GET"])
    @login_required
    def list_admin_models():
        current_user = AuthService.get_current_user()
        if not current_user or not current_user.get("is_admin"):
            raise APIError("Only admin users can view models", status_code=403)
        models = [
            ModelRegistry.to_admin_dict(model)
            for model in ModelRegistry.list_models(app.config["API_BASE_URLS"])
        ]
        return jsonify({"models": models})

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
        start_time = time.time()
        provider = "unknown"
        try:
            payload = json_object_body()
            requested_model = payload.get("model")
            if AutoRouteService.is_auto_route(requested_model):
                raise APIError(
                    "Auto routes currently support /v1/chat/completions and "
                    "/optimize/v1/chat/completions only",
                    status_code=400,
                )
            provider, provider_model, adapter = _resolve_enabled_model(app, requested_model)
            subscription_only = provider == "nanogpt" and nanogpt_subscription_only(
                app.config
            )
            headers_source = (
                sanitize_nanogpt_subscription_headers(request.headers)
                if subscription_only
                else request.headers
            )

            if provider == "kimi-code":
                raise APIError(
                    "Kimi Code does not support the Responses API; use /v1/chat/completions",
                    status_code=400,
                )

            native_responses = provider in NATIVE_RESPONSES_PROVIDERS and (
                provider != "opencode"
                or opencode_model_endpoint(provider_model) == "v1/responses"
            )
            if native_responses and not subscription_only:
                upstream_path = "v1/responses"
                upstream_payload = _copy_request_payload(payload, provider_model)
                upstream_payload = apply_glm_5_reasoning_policy(
                    upstream_payload,
                    provider,
                    provider_model,
                )
                cache_decision = apply_prompt_cache_policy(
                    upstream_payload,
                    provider=provider,
                    model=provider_model,
                    endpoint="responses",
                    request_headers=headers_source,
                    enabled=app.config["PROMPT_CACHE_ENABLED"],
                    minimum_tokens=app.config["PROMPT_CACHE_MIN_TOKENS"],
                )
                upstream_payload = cache_decision.payload
                raw_body = json.dumps(upstream_payload).encode("utf-8")

                def send_request(token: str):
                    headers = proxy_service_cls.prepare_headers(
                        headers_source,
                        provider,
                        token,
                        upstream_path=upstream_path,
                    )
                    _merge_request_headers(headers, cache_decision.request_headers)
                    default_url = (
                        f"{app.config['API_BASE_URLS'][provider].rstrip('/')}"
                        f"/{upstream_path}"
                    )
                    upstream_url = _provider_model_url(
                        app,
                        provider,
                        provider_model,
                        upstream_path,
                        default_url,
                    )
                    return proxy_service_cls.make_request(
                        method="POST",
                        url=upstream_url,
                        headers=headers,
                        params=proxy_service_cls.prepare_params(
                            request.args,
                            provider,
                            token,
                            upstream_path=upstream_path,
                        ),
                        data=raw_body,
                        api_provider=provider,
                        use_cache=False,
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
                    downstream_response = stream_upstream_response(response)
                return _add_credential_attempt_headers(
                    _add_prompt_cache_headers(
                        downstream_response,
                        cache_decision,
                    ),
                    provider,
                    credential_attempts,
                )

            if payload.get("stream"):
                raise APIError("Responses streaming is not supported by the compatibility bridge yet", status_code=400)

            chat_payload = {
                "model": provider_model,
                "messages": responses_input_to_messages(payload),
            }
            for source_key, target_key in {
                "max_output_tokens": "max_tokens",
                "temperature": "temperature",
                "top_p": "top_p",
                "tools": "tools",
                "tool_choice": "tool_choice",
                "reasoning": "reasoning",
                "reasoning_effort": "reasoning_effort",
            }.items():
                if source_key in payload:
                    chat_payload[target_key] = payload[source_key]

            chat_payload = apply_glm_5_reasoning_policy(
                chat_payload,
                provider,
                provider_model,
            )
            cache_decision = apply_prompt_cache_policy(
                chat_payload,
                provider=provider,
                model=provider_model,
                endpoint="chat",
                request_headers=headers_source,
                enabled=app.config["PROMPT_CACHE_ENABLED"],
                minimum_tokens=app.config["PROMPT_CACHE_MIN_TOKENS"],
                nanogpt_subscription_only=subscription_only,
            )
            chat_payload = cache_decision.payload

            raw_body = serialize_unified_chat_payload(chat_payload)
            upstream_path = "v1/chat/completions"

            def send_request(token: str):
                headers = proxy_service_cls.prepare_headers(
                    headers_source,
                    provider,
                    token,
                    upstream_path=upstream_path,
                )
                _merge_request_headers(headers, cache_decision.request_headers)
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
                    "params": request.args,
                    "data": proxy_service_cls.filter_request_data(provider, raw_body),
                    "api_provider": provider,
                    "use_cache": False,
                }
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
            )

            metrics_service_cls.get_instance().track_request(
                provider=provider,
                status_code=response.status_code,
                response_time=(time.time() - start_time) * 1000,
            )

            if isinstance(response, Response):
                return _add_credential_attempt_headers(
                    _add_prompt_cache_headers(response, cache_decision),
                    provider,
                    credential_attempts,
                )
            if not isinstance(response, requests.Response):
                raise APIError("Unsupported upstream response type", status_code=502)
            if response.status_code >= 400:
                return _add_credential_attempt_headers(
                    _add_prompt_cache_headers(
                        _pass_through_response(response),
                        cache_decision,
                    ),
                    provider,
                    credential_attempts,
                )

            chat_response = _decode_upstream_json(response)
            responses_payload = chat_response_to_responses_payload(
                chat_response,
                requested_model,
            )
            downstream_response = jsonify(responses_payload)
            downstream_response.status_code = response.status_code
            return _add_credential_attempt_headers(
                _add_prompt_cache_headers(
                    downstream_response,
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
            )
            raise
