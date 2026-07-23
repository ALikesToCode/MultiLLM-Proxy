import json
import time
import uuid

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
from services.auth_service import AuthService
from services.model_registry import ModelRegistry


RAW_CHAT_PASSTHROUGH_PROVIDERS = frozenset(
    {"codex-easy", "kimi-code", "linkapi", "nanogpt", "navyai"}
)
NATIVE_RESPONSES_PROVIDERS = frozenset(
    {"codex-easy", "linkapi", "nanogpt", "navyai"}
)


def _provider_token(auth_service_cls, provider: str) -> str:
    token = auth_service_cls.get_google_token() if provider == "googleai" else auth_service_cls.get_api_key(provider)
    if not token:
        raise APIError(f"API key not configured for {provider}", status_code=503)
    return token


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


def validate_unified_chat_target(app, auth_service_cls, model_id: str) -> str:
    """Validate model availability and credentials without dispatching upstream."""
    provider, _, _ = _resolve_enabled_model(app, model_id)
    _provider_token(auth_service_cls, provider)
    return provider


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
):
    """Dispatch a validated unified Chat Completions payload."""
    start_time = time.time()
    provider = "unknown"
    headers_source = request.headers if request_headers is None else request_headers
    args_source = request.args if request_args is None else request_args
    try:
        provider, provider_model, adapter = _resolve_enabled_model(
            app,
            payload.get("model"),
        )
        token = _provider_token(auth_service_cls, provider)
        upstream_payload = _copy_request_payload(payload, provider_model)
        raw_body = serialize_unified_chat_payload(upstream_payload)
        upstream_path = "v1/chat/completions"
        headers = proxy_service_cls.prepare_headers(
            headers_source,
            provider,
            token,
            upstream_path=upstream_path,
        )
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

        metrics_service_cls.get_instance().track_request(
            provider=provider,
            status_code=response.status_code,
            response_time=(time.time() - start_time) * 1000,
        )

        if isinstance(response, Response):
            return response
        if provider in RAW_CHAT_PASSTHROUGH_PROVIDERS or payload.get("stream"):
            return stream_upstream_response(response)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get("content-type", "application/json"),
            headers=copy_raw_provider_response_headers(response.headers),
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

        token = _provider_token(auth_service_cls, provider)
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
    @app.route("/v1/models", methods=["GET", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def list_unified_models():
        models = [
            ModelRegistry.to_openai_model_dict(model)
            for model in ModelRegistry.list_models(app.config["API_BASE_URLS"])
            if model.status != "disabled"
        ]
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
            provider, provider_model, adapter = _resolve_enabled_model(app, requested_model)

            if provider == "kimi-code":
                raise APIError(
                    "Kimi Code does not support the Responses API; use /v1/chat/completions",
                    status_code=400,
                )

            token = _provider_token(auth_service_cls, provider)
            if provider in NATIVE_RESPONSES_PROVIDERS:
                upstream_path = "v1/responses"
                upstream_payload = _copy_request_payload(payload, provider_model)
                headers = proxy_service_cls.prepare_headers(
                    request.headers,
                    provider,
                    token,
                    upstream_path=upstream_path,
                )
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

                metrics_service_cls.get_instance().track_request(
                    provider=provider,
                    status_code=response.status_code,
                    response_time=(time.time() - start_time) * 1000,
                )

                if isinstance(response, Response):
                    return response
                return stream_upstream_response(response)

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

            raw_body = serialize_unified_chat_payload(chat_payload)
            headers = proxy_service_cls.prepare_headers(request.headers, provider, token)
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
                return response
            if not isinstance(response, requests.Response):
                raise APIError("Unsupported upstream response type", status_code=502)
            if response.status_code >= 400:
                return _pass_through_response(response)

            chat_response = _decode_upstream_json(response)
            responses_payload = _chat_response_to_responses_payload(chat_response, requested_model)
            return jsonify(responses_payload), response.status_code
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
