import json
import time
import uuid
from collections.abc import Mapping

import requests
from flask import Response, jsonify, request

from error_handlers import APIError
from providers.registry import get_adapter
from route_helpers import (
    api_auth_required,
    copy_raw_provider_response_headers,
    login_required,
    stream_upstream_response,
)
from routes.auto_routes import (
    dispatch_auto_route_chat_completion,
    openai_auto_route_models,
    register_auto_route_admin_routes,
)
from services.adaptive_context_service import apply_adaptive_glm_context
from services.auth_service import AuthService
from services.auto_route_service import AutoRouteService
from services.context_optimizer import ContextOptimizationResult
from services.model_catalog_service import build_model_catalog
from services.model_registry import ModelRegistry
from services.nanogpt_key_pool import NanoGPTKeyPool, NanoGPTKeyPoolExhausted
from services.provider_prompt_cache import (
    PromptCacheDecision,
    apply_prompt_cache_policy,
)
from services.rate_limit_service import RateLimitService
from services.reasoning_policy import apply_glm_52_reasoning_policy
from services.transport_policy import RAW_PASSTHROUGH_PROVIDERS

RAW_CHAT_PASSTHROUGH_PROVIDERS = RAW_PASSTHROUGH_PROVIDERS
NATIVE_RESPONSES_PROVIDERS = frozenset(
    {"codex-easy", "linkapi", "nanogpt", "navyai"}
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
            raise APIError(str(error), status_code=503) from error
    else:
        token = auth_service_cls.get_api_key(provider)
    if not token:
        raise APIError(f"API key not configured for {provider}", status_code=503)
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


def _chat_response_to_responses_payload(chat_payload: dict, requested_model: str) -> dict:
    choices = chat_payload.get("choices") or []
    first_choice = choices[0] if choices else {}
    message = first_choice.get("message") or {}
    text = message.get("content") or ""
    now = int(time.time())
    return {
        "id": chat_payload.get("id", f"resp_{uuid.uuid4().hex}"),
        "object": "response",
        "created_at": now,
        "status": "completed",
        "model": requested_model,
        "output": [
            {
                "id": f"msg_{uuid.uuid4().hex}",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": text,
                        "annotations": [],
                    }
                ],
            }
        ],
        "output_text": text,
        "usage": chat_payload.get("usage"),
    }


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
        token = _provider_token(app, auth_service_cls, proxy_service_cls, provider)
        candidate_payload = _copy_request_payload(payload, provider_model)
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
        upstream_payload = apply_glm_52_reasoning_policy(
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
        )
        upstream_payload = cache_decision.payload
        raw_body = serialize_unified_chat_payload(upstream_payload)
        upstream_path = "v1/chat/completions"
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

        request_data = (
            raw_body
            if provider in RAW_CHAT_PASSTHROUGH_PROVIDERS
            else proxy_service_cls.filter_request_data(provider, raw_body)
        )

        request_kwargs = {
            "method": "POST",
            "url": adapter.chat_completions_url(),
            "headers": headers,
            "params": params,
            "data": request_data,
            "api_provider": provider,
            "use_cache": False,
        }
        if request_timeout is not None:
            request_kwargs["timeout_override"] = request_timeout
        response = proxy_service_cls.make_request(
            **request_kwargs,
        )
        _record_nanogpt_token_result(app, provider, token, response.status_code)

        metrics_service_cls.get_instance().track_request(
            provider=provider,
            status_code=response.status_code,
            response_time=(time.time() - start_time) * 1000,
            model=metrics_model,
            route_decision=route_decision,
        )

        if isinstance(response, Response):
            return _add_prompt_cache_headers(
                _add_adaptive_context_headers(response, adaptive_result),
                cache_decision,
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
        return _add_prompt_cache_headers(
            _add_adaptive_context_headers(
                downstream_response,
                adaptive_result,
            ),
            cache_decision,
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
    """Dispatch an OpenAI Images generation request without changing its response."""
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

        token = _provider_token(app, auth_service_cls, proxy_service_cls, provider)
        upstream_path = "v1/images/generations"
        upstream_payload = _copy_request_payload(payload, provider_model)
        response = proxy_service_cls.make_request(
            method="POST",
            url=f"{app.config['API_BASE_URLS'][provider].rstrip('/')}/{upstream_path}",
            headers=proxy_service_cls.prepare_headers(
                headers_source,
                provider,
                token,
                upstream_path=upstream_path,
            ),
            params=proxy_service_cls.prepare_params(
                args_source,
                provider,
                token,
                upstream_path=upstream_path,
            ),
            data=serialize_unified_chat_payload(upstream_payload),
            api_provider=provider,
            use_cache=False,
        )
        _record_nanogpt_token_result(app, provider, token, response.status_code)

        metrics_service_cls.get_instance().track_request(
            provider=provider,
            status_code=response.status_code,
            response_time=(time.time() - start_time) * 1000,
        )

        if isinstance(response, Response):
            return response
        return stream_upstream_response(response)
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


def _responses_input_to_messages(payload: dict) -> list[dict]:
    messages: list[dict] = []
    instructions = payload.get("instructions")
    if instructions:
        messages.append({"role": "system", "content": instructions})

    input_value = payload.get("input", "")
    if isinstance(input_value, str):
        messages.append({"role": "user", "content": input_value})
    elif isinstance(input_value, list):
        for item in input_value:
            if isinstance(item, dict) and item.get("role") and item.get("content") is not None:
                messages.append({"role": item["role"], "content": item["content"]})
            elif isinstance(item, dict) and item.get("type") in {"message", "input_text"}:
                messages.append({"role": item.get("role", "user"), "content": item.get("content") or item.get("text", "")})
            else:
                messages.append({"role": "user", "content": str(item)})
    else:
        messages.append({"role": "user", "content": str(input_value)})

    return messages


def register_unified_routes(app, csrf, auth_service_cls, metrics_service_cls, proxy_service_cls) -> None:
    register_auto_route_admin_routes(
        app,
        login_required,
        auth_service_cls,
        proxy_service_cls,
    )

    @app.route("/v1/models", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def list_unified_models():
        models = [
            {
                "id": model["id"],
                "object": "model",
                "created": 0,
                "owned_by": model["provider"],
                "status": model["status"],
                "context_window": model["context_window"],
                "max_output_tokens": model["max_output_tokens"],
            }
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
        payload = request.get_json(silent=True) or {}
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
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise APIError("Request body must be a JSON object", status_code=400)
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
            payload = request.get_json(silent=True) or {}
            requested_model = payload.get("model")
            if AutoRouteService.is_auto_route(requested_model):
                raise APIError(
                    "Auto routes currently support /v1/chat/completions and "
                    "/optimize/v1/chat/completions only",
                    status_code=400,
                )
            provider, provider_model, adapter = _resolve_enabled_model(app, requested_model)

            if provider == "kimi-code":
                raise APIError(
                    "Kimi Code does not support the Responses API; use /v1/chat/completions",
                    status_code=400,
                )

            token = _provider_token(
                app,
                auth_service_cls,
                proxy_service_cls,
                provider,
            )
            if provider in NATIVE_RESPONSES_PROVIDERS:
                upstream_path = "v1/responses"
                upstream_payload = _copy_request_payload(payload, provider_model)
                cache_decision = apply_prompt_cache_policy(
                    upstream_payload,
                    provider=provider,
                    model=provider_model,
                    endpoint="responses",
                    request_headers=request.headers,
                    enabled=app.config["PROMPT_CACHE_ENABLED"],
                    minimum_tokens=app.config["PROMPT_CACHE_MIN_TOKENS"],
                )
                upstream_payload = cache_decision.payload
                headers = proxy_service_cls.prepare_headers(
                    request.headers,
                    provider,
                    token,
                    upstream_path=upstream_path,
                )
                _merge_request_headers(headers, cache_decision.request_headers)
                response = proxy_service_cls.make_request(
                    method="POST",
                    url=f"{app.config['API_BASE_URLS'][provider].rstrip('/')}/{upstream_path}",
                    headers=headers,
                    params=proxy_service_cls.prepare_params(
                        request.args,
                        provider,
                        token,
                        upstream_path=upstream_path,
                    ),
                    data=json.dumps(upstream_payload).encode("utf-8"),
                    api_provider=provider,
                    use_cache=False,
                )
                _record_nanogpt_token_result(
                    app,
                    provider,
                    token,
                    response.status_code,
                )

                metrics_service_cls.get_instance().track_request(
                    provider=provider,
                    status_code=response.status_code,
                    response_time=(time.time() - start_time) * 1000,
                )

                if isinstance(response, Response):
                    return _add_prompt_cache_headers(response, cache_decision)
                return _add_prompt_cache_headers(
                    stream_upstream_response(response),
                    cache_decision,
                )

            if payload.get("stream"):
                raise APIError("Responses streaming is not supported by the compatibility bridge yet", status_code=400)

            chat_payload = {
                "model": provider_model,
                "messages": _responses_input_to_messages(payload),
            }
            for source_key, target_key in {
                "max_output_tokens": "max_tokens",
                "temperature": "temperature",
                "top_p": "top_p",
                "tools": "tools",
                "tool_choice": "tool_choice",
            }.items():
                if source_key in payload:
                    chat_payload[target_key] = payload[source_key]

            cache_decision = apply_prompt_cache_policy(
                chat_payload,
                provider=provider,
                model=provider_model,
                endpoint="chat",
                request_headers=request.headers,
                enabled=app.config["PROMPT_CACHE_ENABLED"],
                minimum_tokens=app.config["PROMPT_CACHE_MIN_TOKENS"],
            )
            chat_payload = cache_decision.payload

            raw_body = serialize_unified_chat_payload(chat_payload)
            headers = proxy_service_cls.prepare_headers(request.headers, provider, token)
            _merge_request_headers(headers, cache_decision.request_headers)
            response = proxy_service_cls.make_request(
                method="POST",
                url=adapter.chat_completions_url(),
                headers=headers,
                params=request.args,
                data=proxy_service_cls.filter_request_data(provider, raw_body),
                api_provider=provider,
                use_cache=False,
            )

            metrics_service_cls.get_instance().track_request(
                provider=provider,
                status_code=response.status_code,
                response_time=(time.time() - start_time) * 1000,
            )

            if isinstance(response, Response):
                return _add_prompt_cache_headers(response, cache_decision)
            if not isinstance(response, requests.Response):
                raise APIError("Unsupported upstream response type", status_code=502)
            if response.status_code >= 400:
                return _add_prompt_cache_headers(
                    _pass_through_response(response),
                    cache_decision,
                )

            chat_response = _decode_upstream_json(response)
            responses_payload = _chat_response_to_responses_payload(chat_response, requested_model)
            downstream_response = jsonify(responses_payload)
            downstream_response.status_code = response.status_code
            return _add_prompt_cache_headers(
                downstream_response,
                cache_decision,
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
