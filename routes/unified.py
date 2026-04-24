import json
import time
import uuid

import requests
from flask import Response, jsonify, request

from error_handlers import APIError
from providers.registry import get_adapter
from route_helpers import api_auth_required, copy_upstream_response_headers, login_required
from services.auth_service import AuthService
from services.model_registry import ModelRegistry


def _provider_token(auth_service_cls, provider: str) -> str:
    token = auth_service_cls.get_google_token() if provider == "googleai" else auth_service_cls.get_api_key(provider)
    if not token:
        raise APIError(f"API key not configured for {provider}", status_code=502)
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
        ModelRegistry.parse_model_id(model_id)
        ModelRegistry.disable_model(model_id)
        return jsonify({"model": model_id, "status": "disabled"})

    @app.route("/v1/chat/completions", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def unified_chat_completions():
        start_time = time.time()
        provider = "unknown"
        try:
            payload = request.get_json(silent=True) or {}
            provider, provider_model, adapter = _resolve_enabled_model(app, payload.get("model"))
            token = _provider_token(auth_service_cls, provider)
            upstream_payload = _copy_request_payload(payload, provider_model)
            raw_body = json.dumps(upstream_payload).encode("utf-8")
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
            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get("content-type", "application/json"),
                headers=copy_upstream_response_headers(response.headers),
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

    @app.route("/v1/responses", methods=["POST", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def unified_responses():
        start_time = time.time()
        provider = "unknown"
        try:
            payload = request.get_json(silent=True) or {}
            if payload.get("stream"):
                raise APIError("Responses streaming is not supported by the compatibility bridge yet", status_code=400)

            requested_model = payload.get("model")
            provider, provider_model, adapter = _resolve_enabled_model(app, requested_model)
            token = _provider_token(auth_service_cls, provider)
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

            raw_body = json.dumps(chat_payload).encode("utf-8")
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

            chat_response = _decode_upstream_json(response) if isinstance(response, requests.Response) else {}
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
