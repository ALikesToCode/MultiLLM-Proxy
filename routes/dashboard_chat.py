"""Session-authenticated dashboard chat dispatch."""

import json
import logging
import os
import time

from flask import Response, request

from error_handlers import APIError
from providers.registry import get_adapter
from proxy import PROVIDER_DETAILS
from request_validation import json_object_body
from route_helpers import copy_upstream_response_headers, login_required
from routes.unified import dispatch_unified_chat_completion

logger = logging.getLogger(__name__)


def _dashboard_chat_completions_url(app, provider):
    if provider == "googleai":
        project_id = os.environ.get("PROJECT_ID")
        location = os.environ.get("LOCATION")
        endpoint = os.environ.get("GOOGLE_ENDPOINT")
        missing = [
            name
            for name, value in {
                "PROJECT_ID": project_id,
                "LOCATION": location,
                "GOOGLE_ENDPOINT": endpoint,
            }.items()
            if not value
        ]
        if missing:
            raise APIError(
                f"Missing Google AI configuration: {', '.join(missing)}",
                status_code=503,
            )
        return (
            f"https://{endpoint}/v1beta1/projects/{project_id}/locations/"
            f"{location}/endpoints/openapi/chat/completions"
        )

    adapter = get_adapter(provider, app.config["API_BASE_URLS"])
    if not adapter or not adapter.capabilities().supports_chat:
        raise APIError(
            f"Chat completions are not supported for provider: {provider}",
            status_code=400,
        )
    return adapter.chat_completions_url()


def register_dashboard_chat_routes(
    app, auth_service_cls, metrics_service_cls, proxy_service_cls
):
    @app.route("/api/backends/chat-completions/generate", methods=["POST"])
    @login_required
    def proxy_chat_completions():
        """
        Handle chat completion requests and proxy them to the selected backend.
        """
        start_time = time.time()
        provider = None
        try:
            data = json_object_body()

            provider = data.get("provider", "").lower()
            if not provider:
                raise APIError("No provider specified", status_code=400)
            if provider not in PROVIDER_DETAILS:
                raise APIError(f"Unsupported provider: {provider}", status_code=400)

            if provider == "anthropic":
                payload = {
                    key: value for key, value in data.items() if key != "provider"
                }
                model = payload.get("model")
                if not isinstance(model, str) or not model:
                    raise APIError("Model field is required", status_code=400)
                if not model.startswith("anthropic:"):
                    payload["model"] = f"anthropic:{model}"
                return dispatch_unified_chat_completion(
                    app,
                    auth_service_cls,
                    metrics_service_cls,
                    proxy_service_cls,
                    payload,
                )

            if provider == "googleai":
                auth_token = auth_service_cls.get_google_token()
                if not auth_token:
                    raise APIError(
                        "Google AI authentication token not configured", status_code=503
                    )
            else:
                auth_token = auth_service_cls.get_api_key(provider)
                if not auth_token:
                    raise APIError(
                        f"{provider.upper()} API key not configured", status_code=503
                    )

            url = _dashboard_chat_completions_url(app, provider)
            upstream_payload = {
                key: value for key, value in data.items() if key != "provider"
            }
            raw_body = json.dumps(upstream_payload).encode("utf-8")
            headers = proxy_service_cls.prepare_headers(
                request.headers, provider, auth_token
            )
            request_data = proxy_service_cls.filter_request_data(provider, raw_body)

            response = proxy_service_cls.make_request(
                method="POST",
                url=url,
                headers=headers,
                params=request.args,
                data=request_data,
                api_provider=provider,
                use_cache=False,
            )

            response_time = (time.time() - start_time) * 1000
            status_code = getattr(response, "status_code", 200)
            metrics_service_cls.get_instance().track_request(
                provider=provider,
                status_code=status_code,
                response_time=response_time,
            )

            if isinstance(response, Response):
                return response

            return Response(
                response.content,
                status=status_code,
                content_type=response.headers.get("content-type", "application/json"),
                headers=copy_upstream_response_headers(response.headers),
            )

        except APIError as error:
            logger.error(
                "Chat completions API error status=%s",
                error.status_code,
            )
            if provider:
                metrics_service_cls.get_instance().track_request(
                    provider=provider,
                    status_code=error.status_code,
                    response_time=(time.time() - start_time) * 1000,
                )
            raise

        except Exception as error:
            logger.error(
                "Unexpected chat completions error type=%s",
                type(error).__name__,
            )
            if provider:
                metrics_service_cls.get_instance().track_request(
                    provider=provider,
                    status_code=502,
                    response_time=(time.time() - start_time) * 1000,
                )
            raise APIError(
                "Dashboard chat completions proxy failed", status_code=502
            ) from error
