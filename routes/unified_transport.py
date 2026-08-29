from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from flask import Response

from error_handlers import APIError
from providers.aihubmix import (
    build_aihubmix_url,
    normalize_aihubmix_image_response,
    request_with_origin_fallback,
)
from providers.image_relays import image_relay_backup_base_url
from route_helpers import copy_raw_provider_response_headers


def send_unified_provider_request(
    proxy_service_cls,
    request_kwargs: dict[str, Any],
    *,
    provider: str,
    primary_origin: str,
    secondary_origin: str | None,
    upstream_path: str,
    request_headers: Mapping[str, Any],
):
    """Send one unified request with bounded, replay-safe origin fallback."""
    secondary_origin = secondary_origin or image_relay_backup_base_url(provider)
    if secondary_origin is None and provider != "aihubmix":
        return proxy_service_cls.make_request(**request_kwargs)
    if secondary_origin is None:
        raise APIError("AIHubMix backup origin is not configured", status_code=500)

    return request_with_origin_fallback(
        lambda origin: proxy_service_cls.make_request(
            **{
                **request_kwargs,
                "url": build_aihubmix_url(origin, upstream_path),
            }
        ),
        primary_origin=primary_origin,
        secondary_origin=secondary_origin,
        method=str(request_kwargs.get("method", "GET")),
        request_headers=request_headers,
    )


def send_configured_unified_provider_request(
    proxy_service_cls,
    request_kwargs: dict[str, Any],
    *,
    provider: str,
    runtime_config: Mapping[str, Any],
    upstream_path: str,
    request_headers: Mapping[str, Any],
):
    """Resolve configured origins before applying provider transport policy."""
    return send_unified_provider_request(
        proxy_service_cls,
        request_kwargs,
        provider=provider,
        primary_origin=runtime_config["API_BASE_URLS"][provider],
        secondary_origin=(
            runtime_config.get("AIHUBMIX_BACKUP_BASE_URL")
            if provider == "aihubmix"
            else None
        ),
        upstream_path=upstream_path,
        request_headers=request_headers,
    )


def send_unified_image_request(
    proxy_service_cls,
    *,
    provider: str,
    token: str,
    request_headers: Mapping[str, Any],
    request_args: Mapping[str, Any],
    upstream_path: str,
    raw_body: bytes,
    primary_origin: str,
    secondary_origin: str | None = None,
):
    """Prepare and send a unified image request without changing its body."""
    request_kwargs = {
        "method": "POST",
        "url": build_aihubmix_url(primary_origin, upstream_path),
        "headers": proxy_service_cls.prepare_headers(
            request_headers,
            provider,
            token,
            upstream_path=upstream_path,
        ),
        "params": proxy_service_cls.prepare_params(
            request_args,
            provider,
            token,
            upstream_path=upstream_path,
        ),
        "data": raw_body,
        "api_provider": provider,
        "use_cache": False,
        "force_raw_passthrough": True,
    }
    return send_unified_provider_request(
        proxy_service_cls,
        request_kwargs,
        provider=provider,
        primary_origin=primary_origin,
        secondary_origin=secondary_origin,
        upstream_path=upstream_path,
        request_headers=request_headers,
    )


def normalized_aihubmix_image_response(
    response,
    response_kind: str,
) -> Response | None:
    """Convert translated AIHubMix success bodies back to OpenAI Images."""
    if response.status_code >= 400 or response_kind == "openai":
        return None

    try:
        try:
            native_payload = response.json()
        except ValueError as error:
            raise APIError(
                "AIHubMix returned a non-JSON image response",
                status_code=502,
            ) from error
        if not isinstance(native_payload, Mapping):
            raise APIError(
                "AIHubMix returned an unsupported image response",
                status_code=502,
            )
        try:
            normalized_payload = normalize_aihubmix_image_response(
                response_kind,
                native_payload,
            )
        except ValueError as error:
            raise APIError(
                "AIHubMix returned an invalid image response",
                status_code=502,
            ) from error
        return Response(
            json.dumps(normalized_payload, separators=(",", ":")),
            status=response.status_code,
            content_type="application/json",
            headers=copy_raw_provider_response_headers(response.headers),
        )
    finally:
        response.close()
