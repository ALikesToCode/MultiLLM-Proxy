"""Provider transport for image generation, shared by QA and ordinary requests."""

import time

from flask import Response, request

from error_handlers import APIError
from providers.aihubmix import build_aihubmix_image_request
from providers.gpt_image_moderation import apply_gpt_image_moderation_default
from route_helpers import stream_upstream_response
from routes.media_images import dispatch_auto_image_generation
from routes.provider_credentials import _add_credential_attempt_headers, _request_with_provider_token_rotation
from routes.unified_transport import normalized_aihubmix_image_response, send_unified_image_request
from services import cloudflare_ai
from services.auto_route_service import AutoRouteService
from services.media_catalog import TRANSPORT_FAILURE_HEADER


def dispatch_image_generation_raw(
    app,
    auth_service_cls,
    metrics_service_cls,
    proxy_service_cls,
    payload: dict,
    *,
    resolve_model,
    validate_candidate,
    serialize_payload,
    request_headers=None,
    request_args=None,
):
    """Dispatch an OpenAI Images request, translating provider-native models."""
    if AutoRouteService.is_auto_route(payload.get("model")):
        return dispatch_auto_image_generation(
            payload,
            validate_candidate=validate_candidate,
            dispatch_candidate=lambda candidate_payload: dispatch_image_generation_raw(
                app,
                auth_service_cls,
                metrics_service_cls,
                proxy_service_cls,
                candidate_payload,
                resolve_model=resolve_model,
                validate_candidate=validate_candidate,
                serialize_payload=serialize_payload,
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
        provider, provider_model, adapter = resolve_model(payload.get("model"))
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
            upstream_payload = {**payload, "model": provider_model}
        raw_body = serialize_payload(upstream_payload)
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
