import gzip
import io
import json
import logging
import os
import time
from urllib.parse import unquote

from flask import Response, jsonify, request

from error_handlers import APIError
from providers.nanogpt import (
    build_nanogpt_url,
    is_nanogpt_accountless_request,
    is_nanogpt_interactive_browser_request,
    is_nanogpt_public_request,
    nanogpt_allows_missing_api_key,
    nanogpt_has_caller_auth,
)
from providers.navyai import (
    is_navyai_interactive_oauth_request,
    is_navyai_public_request,
    navyai_has_caller_auth,
)
from providers.opencode_go import (
    build_opencode_go_url,
    is_opencode_go_native_request,
    opencode_go_has_caller_auth,
)
from providers.registry import get_adapter
from proxy import PROVIDER_DETAILS
from route_helpers import (
    api_auth_required,
    copy_upstream_response_headers,
    login_required,
    stream_upstream_response,
)

logger = logging.getLogger(__name__)

RAW_PASSTHROUGH_PROVIDERS = frozenset(
    {"codex-easy", "kimi-code", "linkapi", "nanogpt", "navyai"}
)
CODEX_EASY_EXACT_PATHS = frozenset(
    {
        "v1/models",
        "v1/responses",
        "v1/chat/completions",
        "v1/images",
    }
)
KIMI_CODE_METHODS_BY_PATH = {
    "v1/models": frozenset({"GET"}),
    "v1/chat/completions": frozenset({"POST"}),
}


def _is_valid_codex_easy_path(path: str) -> bool:
    """Allow only the documented Codex Everywhere OpenAI-compatible surface."""
    if not path or any(delimiter in path for delimiter in "%?#\\"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return False
    if path in CODEX_EASY_EXACT_PATHS:
        return True
    if not path.startswith("v1/images/"):
        return False
    return all(segment not in {"", ".", ".."} for segment in path.split("/"))


def _is_valid_kimi_code_request(path: str, method: str) -> bool:
    """Allow only Kimi Code's documented OpenAI-compatible routes."""
    if not path or any(delimiter in path for delimiter in "%?#\\"):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        return False
    return method.upper() in KIMI_CODE_METHODS_BY_PATH.get(path, frozenset())


def _is_encoded_kimi_code_namespace(provider: str) -> bool:
    candidate = provider.lower()
    for _ in range(4):
        if candidate == "kimi-code" or candidate.startswith(
            ("kimi-code%", "kimi-code/", "kimi-code\\")
        ):
            return True
        if "%" not in candidate:
            return False
        decoded_candidate = unquote(candidate)
        if decoded_candidate == candidate:
            return False
        candidate = decoded_candidate
    return False

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
            raise APIError(f"Missing Google AI configuration: {', '.join(missing)}", status_code=503)
        return (
            f"https://{endpoint}/v1beta1/projects/{project_id}/locations/"
            f"{location}/endpoints/openapi/chat/completions"
        )

    adapter = get_adapter(provider, app.config["API_BASE_URLS"])
    if not adapter or not adapter.capabilities().supports_chat:
        raise APIError(f"Chat completions are not supported for provider: {provider}", status_code=400)
    return adapter.chat_completions_url()


def register_proxy_routes(app, csrf, auth_service_cls, metrics_service_cls, proxy_service_cls) -> None:
    @app.route("/<api_provider>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    @app.route("/<api_provider>/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    @csrf.exempt
    @api_auth_required
    def proxy(api_provider: str, path: str = ""):
        """
        Proxy requests to the appropriate API provider.
        """
        start_time = time.time()
        raw_passthrough = False
        try:
            if api_provider != "kimi-code" and _is_encoded_kimi_code_namespace(
                api_provider
            ):
                api_provider = "kimi-code"
                raise APIError("Invalid Kimi Code path", status_code=400)
            if api_provider not in app.config["API_BASE_URLS"]:
                raise APIError(f"Unsupported API provider: {api_provider}", status_code=400)
            if api_provider == "linkapi" and any(delimiter in path for delimiter in "?#"):
                raise APIError("Invalid LinkAPI path", status_code=400)
            if api_provider == "codex-easy" and not _is_valid_codex_easy_path(path):
                raise APIError("Invalid Codex Everywhere path", status_code=400)
            if api_provider == "kimi-code" and not _is_valid_kimi_code_request(
                path,
                request.method,
            ):
                raise APIError("Invalid Kimi Code path", status_code=400)
            if api_provider == "navyai" and is_navyai_interactive_oauth_request(
                path,
                request.method,
            ):
                raise APIError(
                    "Start NavyAI OAuth directly at "
                    "https://api.navy/v1/oauth/authorize; browser redirects and "
                    "session cookies are not proxied",
                    status_code=400,
                )
            if api_provider == "nanogpt" and is_nanogpt_interactive_browser_request(
                path,
                request.method,
            ):
                raise APIError(
                    "Start NanoGPT browser authentication directly at "
                    "https://nano-gpt.com/auth or "
                    "https://nano-gpt.com/oauth/authorize; browser redirects "
                    "and session cookies are not proxied",
                    status_code=400,
                )

            raw_passthrough = (
                api_provider in RAW_PASSTHROUGH_PROVIDERS
                or (
                    api_provider == "opencode"
                    and is_opencode_go_native_request(path, request.method)
                )
            )

            base_url = app.config["API_BASE_URLS"][api_provider]
            if api_provider == "groq":
                if path.startswith("v1/"):
                    path = f"openai/{path}"
                elif path and not path.startswith("openai/"):
                    path = f"openai/v1/{path}"
                elif not path:
                    path = "openai/v1"
            elif api_provider == "nineteen":
                if path in {"v1/chat/completions", "v1/completions"}:
                    pass
            elif api_provider == "kimi-code":
                path = path.removeprefix("v1/")
            elif api_provider == "googleai" and path == "models":
                project_id = os.environ.get("PROJECT_ID")
                location = os.environ.get("LOCATION")
                endpoint = os.environ.get("GOOGLE_ENDPOINT")
                if not project_id:
                    raise APIError("PROJECT_ID environment variable not set", status_code=500)
                if not location:
                    raise APIError("LOCATION environment variable not set", status_code=500)
                if not endpoint:
                    raise APIError("ENDPOINT environment variable not set", status_code=500)
                base_url = (
                    f"https://{endpoint}/v1beta1/projects/"
                    f"{project_id}/locations/{location}/models"
                )
                path = ""

            if api_provider == "nanogpt":
                url = build_nanogpt_url(
                    base_url,
                    app.config["NANOGPT_BATCH_BASE_URL"],
                    path,
                    app.config["NANOGPT_ORIGIN_URL"],
                )
            elif api_provider == "opencode":
                url = build_opencode_go_url(base_url, path)
            else:
                url = f"{base_url}/{path}" if path else base_url
            if raw_passthrough:
                logger.info("Proxying raw request for %s", api_provider)
            else:
                logger.info("Proxying request to: %s", url)

            if api_provider == "googleai":
                auth_token = auth_service_cls.get_google_token()
            else:
                auth_token = auth_service_cls.get_api_key(api_provider)

            if (
                api_provider == "nanogpt"
                and (
                    is_nanogpt_accountless_request(request.headers, path)
                    or is_nanogpt_public_request(path, request.method)
                )
            ):
                auth_token = None
            elif (
                api_provider == "navyai"
                and is_navyai_public_request(path, request.method)
            ):
                auth_token = None

            missing_key_allowed = (
                api_provider == "nanogpt"
                and nanogpt_allows_missing_api_key(
                    request.headers,
                    path,
                    request.method,
                )
            )
            if api_provider == "nanogpt":
                missing_key_allowed = (
                    missing_key_allowed
                    or nanogpt_has_caller_auth(request.headers)
                )
            if api_provider == "navyai":
                missing_key_allowed = (
                    is_navyai_public_request(path, request.method)
                    or navyai_has_caller_auth(request.headers)
                )
            if api_provider == "opencode":
                missing_key_allowed = opencode_go_has_caller_auth(request.headers)
            if not auth_token and not missing_key_allowed:
                raise APIError(f"API key not configured for {api_provider}", status_code=503)

            is_streaming = False
            if request.is_json:
                try:
                    body = request.get_json()
                    is_streaming = bool(body.get("stream", False))
                except Exception:
                    pass

            headers = proxy_service_cls.prepare_headers(
                request.headers,
                api_provider,
                auth_token,
                upstream_path=path,
            )
            if (
                api_provider in {"nanogpt", "navyai", "opencode"}
                and is_streaming
                and not proxy_service_cls._has_header(headers, "Accept")
            ):
                headers["Accept"] = "text/event-stream"
            params = (
                proxy_service_cls.prepare_params(
                    request.args,
                    api_provider,
                    auth_token,
                    upstream_path=path,
                )
                if raw_passthrough
                else request.args
            )
            raw_request_data = request.get_data()
            request_data = (
                raw_request_data
                if raw_passthrough
                else proxy_service_cls.filter_request_data(api_provider, raw_request_data)
            )

            response = proxy_service_cls.make_request(
                method=request.method,
                url=url,
                headers=headers,
                params=params,
                data=request_data,
                api_provider=api_provider,
                use_cache=(
                    request.method.upper() == "GET"
                    and not is_streaming
                    and not raw_passthrough
                ),
                force_raw_passthrough=raw_passthrough,
            )

            response_time = (time.time() - start_time) * 1000
            metrics_service_cls.get_instance().track_request(
                provider=api_provider,
                status_code=response.status_code,
                response_time=response_time,
            )

            if raw_passthrough:
                if isinstance(response, Response):
                    return response
                return stream_upstream_response(response)

            if is_streaming and response.headers.get("content-type", "").startswith("text/event-stream"):
                if isinstance(response, Response):
                    return response

                def standardize_streaming_chunk(chunk, provider_name):
                    """Use ProxyService's shared stream normalizer to avoid drift."""
                    try:
                        return proxy_service_cls._standardize_streaming_chunk(chunk, provider_name)
                    except Exception as error:
                        logger.error("Error standardizing chunk: %s", error)
                        fallback = {
                            "id": f"chatcmpl-{str(int(time.time()))[:10]}",
                            "object": "chat.completion.chunk",
                            "choices": [{"delta": {"content": str(chunk)}}],
                        }
                        return f"data: {json.dumps(fallback)}\n\n"

                def generate_stream():
                    done_sent = False
                    try:
                        for chunk in response.iter_lines(decode_unicode=True):
                            standardized_chunk = standardize_streaming_chunk(chunk, api_provider)
                            if standardized_chunk:
                                if standardized_chunk.strip() == "data: [DONE]":
                                    done_sent = True
                                    yield standardized_chunk
                                    if hasattr(response, "close"):
                                        response.close()
                                    return
                                yield standardized_chunk
                        if not done_sent:
                            yield "data: [DONE]\n\n"
                    except Exception as error:
                        logger.error("Error in streaming response: %s", error)
                        error_chunk = {
                            "id": f"chatcmpl-{str(int(time.time()))[:10]}",
                            "object": "chat.completion.chunk",
                            "choices": [{"delta": {"content": f"Error: {str(error)}"}}],
                        }
                        yield f"data: {json.dumps(error_chunk)}\n\n"
                        yield "data: [DONE]\n\n"
                    finally:
                        if hasattr(response, "close"):
                            response.close()

                return Response(
                    generate_stream(),
                    status=response.status_code,
                    content_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                    },
                )

            return Response(
                response.content,
                status=response.status_code,
                content_type=response.headers.get("content-type", "application/json"),
                headers=copy_upstream_response_headers(response.headers),
            )

        except Exception as error:
            response_time = (time.time() - start_time) * 1000
            status_code = error.status_code if isinstance(error, APIError) else 500

            metrics_service_cls.get_instance().track_request(
                provider=api_provider,
                status_code=status_code,
                response_time=response_time,
            )
            if raw_passthrough:
                logger.error(
                    "Raw proxy request failed for %s (%s)",
                    api_provider,
                    type(error).__name__,
                )
            else:
                logger.error("Proxy error for %s: %s", api_provider, error)
            if isinstance(error, APIError):
                raise error
            if raw_passthrough:
                raise APIError("Upstream proxy request failed", status_code=502)
            raise APIError(f"Proxy error: {str(error)}", status_code=500)

    @app.route("/api/backends/chat-completions/generate", methods=["POST"])
    @login_required
    def proxy_chat_completions():
        """
        Handle chat completion requests and proxy them to the selected backend.
        """
        start_time = time.time()
        provider = None
        try:
            data = request.get_json()
            if not data:
                raise APIError("No request data provided", status_code=400)

            provider = data.get("provider", "").lower()
            if not provider:
                raise APIError("No provider specified", status_code=400)
            if provider not in PROVIDER_DETAILS:
                raise APIError(f"Unsupported provider: {provider}", status_code=400)

            if provider == "googleai":
                auth_token = auth_service_cls.get_google_token()
                if not auth_token:
                    raise APIError("Google AI authentication token not configured", status_code=503)
            else:
                auth_token = auth_service_cls.get_api_key(provider)
                if not auth_token:
                    raise APIError(f"{provider.upper()} API key not configured", status_code=503)

            url = _dashboard_chat_completions_url(app, provider)
            upstream_payload = {
                key: value
                for key, value in data.items()
                if key != "provider"
            }
            raw_body = json.dumps(upstream_payload).encode("utf-8")
            headers = proxy_service_cls.prepare_headers(request.headers, provider, auth_token)
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
            logger.error("API Error in chat completions: %s", error.message)
            if provider:
                metrics_service_cls.get_instance().track_request(
                    provider=provider,
                    status_code=error.status_code,
                    response_time=(time.time() - start_time) * 1000,
                )
            raise

        except Exception as error:
            logger.exception("Unexpected error in chat completions")
            if provider:
                metrics_service_cls.get_instance().track_request(
                    provider=provider,
                    status_code=502,
                    response_time=(time.time() - start_time) * 1000,
                )
            raise APIError("Dashboard chat completions proxy failed", status_code=502) from error

    @app.route("/googleai/chat/completions", methods=["POST"])
    @csrf.exempt
    @api_auth_required
    def google_chat_completions():
        """
        Specific endpoint for Google AI chat completions.
        """
        start_time = time.time()
        try:
            data = request.get_json()
            if not data:
                raise APIError("No request data provided")

            if "messages" not in data:
                raise APIError("Messages array is required", status_code=400)

            messages = data["messages"]
            if not isinstance(messages, list):
                raise APIError("Messages must be an array", status_code=400)
            if not messages:
                raise APIError("Messages array cannot be empty", status_code=400)

            for message in messages:
                if not isinstance(message, dict):
                    raise APIError("Each message must be an object", status_code=400)
                if "role" not in message:
                    raise APIError("Each message must have a 'role' field", status_code=400)
                if "content" not in message:
                    raise APIError("Each message must have a 'content' field", status_code=400)

            def get_fresh_token():
                token = auth_service_cls.get_google_token()
                if not token:
                    raise APIError("Google AI authentication token not configured", status_code=401)
                return token

            try:
                google_token = get_fresh_token()
                proxy_service = proxy_service_cls()

                project_id = os.environ.get("PROJECT_ID")
                location = os.environ.get("LOCATION")
                endpoint = os.environ.get("GOOGLE_ENDPOINT")
                url = (
                    f"https://{endpoint}/v1beta1/projects/{project_id}/locations/"
                    f"{location}/endpoints/openapi/chat/completions"
                )
                headers = proxy_service_cls.prepare_headers(request.headers, "googleai", google_token)

                request_data = {
                    "model": data.get("model", "meta/llama-3.1-405b-instruct-maas"),
                    "messages": messages,
                    "max_tokens": data.get("max_tokens", 1024),
                    "stream": data.get("stream", False),
                    "extra_body": data.get(
                        "extra_body",
                        {
                            "google": {
                                "model_safety_settings": {
                                    "enabled": False,
                                    "llama_guard_settings": {},
                                }
                            }
                        },
                    ),
                }

                if "stream" in data:
                    request_data["stream"] = bool(data["stream"])
                    logger.debug("Google AI stream parameter explicitly set to: %s", request_data["stream"])

                logger.debug("Prepared request data: %s", json.dumps(request_data))

                response = proxy_service.make_request(
                    method="POST",
                    url=url,
                    headers=headers,
                    params=request.args,
                    data=json.dumps(request_data).encode("utf-8"),
                    api_provider="googleai",
                    use_cache=False,
                )

                if response.status_code == 401:
                    logger.info("Received 401, refreshing Google token and retrying...")
                    auth_service_cls._google_token = None
                    auth_service_cls._google_token_expiry = None

                    google_token = get_fresh_token()
                    headers = proxy_service_cls.prepare_headers(request.headers, "googleai", google_token)
                    response = proxy_service.make_request(
                        method="POST",
                        url=url,
                        headers=headers,
                        params=request.args,
                        data=json.dumps(request_data).encode("utf-8"),
                        api_provider="googleai",
                        use_cache=False,
                    )

                response_time = (time.time() - start_time) * 1000
                metrics_service_cls.get_instance().track_request(
                    provider="googleai",
                    status_code=response.status_code,
                    response_time=response_time,
                )

                if request_data.get("stream", False):
                    logger.info(
                        "Handling Google AI streaming response, status: %s, headers: %s",
                        response.status_code,
                        response.headers,
                    )

                    if response.status_code != 200:
                        logger.error("Google AI streaming error: HTTP %s", response.status_code)
                        error_msg = f"Google AI streaming failed with HTTP {response.status_code}"
                        try:
                            error_data = response.json()
                            if isinstance(error_data, dict) and "error" in error_data:
                                error_msg = f"Google AI error: {error_data['error']}"
                        except Exception:
                            try:
                                error_msg = f"Google AI error: {response.text[:200]}"
                            except Exception:
                                pass

                        def error_stream():
                            error_chunk = {
                                "id": f"chatcmpl-{str(int(time.time()))[:10]}",
                                "object": "chat.completion.chunk",
                                "created": int(time.time()),
                                "model": "googleai-stream",
                                "choices": [{"delta": {"content": error_msg}}],
                            }
                            yield f"data: {json.dumps(error_chunk)}\n\n"
                            yield "data: [DONE]\n\n"

                        return Response(
                            error_stream(),
                            mimetype="text/event-stream",
                            headers={
                                "Cache-Control": "no-cache",
                                "Content-Type": "text/event-stream",
                                "X-Accel-Buffering": "no",
                            },
                        )

                    def generate():
                        try:
                            def standardize_streaming_chunk(chunk, provider_name):
                                """Standardize streaming chunks to OpenAI format"""
                                try:
                                    if chunk.startswith("data: ") and ("delta" in chunk or chunk.strip() == "data: [DONE]"):
                                        return chunk

                                    if chunk.strip() in ("[DONE]", "data: [DONE]"):
                                        return "data: [DONE]\n\n"

                                    content = None
                                    try:
                                        if chunk.startswith("data: "):
                                            data_str = chunk[6:].strip()
                                            if data_str == "[DONE]":
                                                return "data: [DONE]\n\n"
                                            parsed = json.loads(data_str)

                                            if provider_name == "anthropic" and "completion" in parsed:
                                                content = parsed.get("completion", "")
                                            elif provider_name in ("gemini", "gemma") and "candidates" in parsed:
                                                content = parsed["candidates"][0]["content"]["parts"][0]["text"]
                                            elif "choices" in parsed and len(parsed["choices"]) > 0:
                                                choice = parsed["choices"][0]
                                                if "delta" in choice and "content" in choice["delta"]:
                                                    content = choice["delta"]["content"]
                                                elif "text" in choice:
                                                    content = choice["text"]
                                            elif "text" in parsed:
                                                content = parsed["text"]
                                        else:
                                            content = chunk
                                    except Exception:
                                        content = chunk

                                    if content is None:
                                        content = chunk

                                    openai_chunk = {
                                        "id": f"chatcmpl-{str(int(time.time()))[:10]}",
                                        "object": "chat.completion.chunk",
                                        "created": int(time.time()),
                                        "model": f"{provider_name}-stream",
                                        "choices": [{"delta": {"content": content}}],
                                    }

                                    return f"data: {json.dumps(openai_chunk)}\n\n"
                                except Exception as error:
                                    logger.error("Error standardizing chunk: %s", error)
                                    fallback = {
                                        "id": f"chatcmpl-{str(int(time.time()))[:10]}",
                                        "object": "chat.completion.chunk",
                                        "choices": [{"delta": {"content": str(chunk)}}],
                                    }
                                    return f"data: {json.dumps(fallback)}\n\n"

                            is_gzipped = response.headers.get("content-encoding", "").lower() == "gzip"

                            if hasattr(response, "raw"):
                                buffer = io.BytesIO()
                                while True:
                                    chunk = response.raw.read(1024)
                                    if not chunk:
                                        break

                                    if is_gzipped:
                                        buffer.write(chunk)
                                    else:
                                        try:
                                            chunk_str = chunk.decode("utf-8").strip()
                                            if chunk_str:
                                                for line in chunk_str.split("\n"):
                                                    line = line.strip()
                                                    if line:
                                                        yield standardize_streaming_chunk(line, "googleai")
                                        except Exception as error:
                                            logger.error("Error processing chunk: %s", error)
                                            continue

                                if is_gzipped:
                                    try:
                                        buffer.seek(0)
                                        with gzip.GzipFile(fileobj=buffer, mode="rb") as gzipped:
                                            decompressed = gzipped.read().decode("utf-8")
                                            for line in decompressed.split("\n"):
                                                line = line.strip()
                                                if line:
                                                    yield standardize_streaming_chunk(line, "googleai")
                                    except Exception as error:
                                        logger.error("Error decompressing gzipped response: %s", error)
                            else:
                                for line in response.iter_lines(decode_unicode=True):
                                    if line:
                                        yield standardize_streaming_chunk(line, "googleai")

                            yield "data: [DONE]\n\n"
                        except Exception as error:
                            logger.error("Error in streaming response: %s", error)
                            error_chunk = {
                                "id": f"chatcmpl-{str(int(time.time()))[:10]}",
                                "object": "chat.completion.chunk",
                                "choices": [{"delta": {"content": f"Error: {str(error)}"}}],
                            }
                            yield f"data: {json.dumps(error_chunk)}\n\n"
                            yield "data: [DONE]\n\n"

                    return Response(
                        generate(),
                        mimetype="text/event-stream",
                        headers={
                            "Cache-Control": "no-cache",
                            "Content-Type": "text/event-stream",
                            "X-Accel-Buffering": "no",
                        },
                    )

                try:
                    response_json = response.json()
                    return jsonify(response_json), response.status_code
                except (json.JSONDecodeError, AttributeError):
                    content = response.content if hasattr(response, "content") else response.get_data()
                    if response.headers.get("content-encoding", "").lower() == "gzip":
                        content = gzip.decompress(content)

                    return Response(
                        content,
                        status=response.status_code,
                        content_type=response.headers.get("content-type", "application/json"),
                    )

            except APIError as error:
                logger.error("API Error in Google chat completions: %s", error.message)
                response_time = (time.time() - start_time) * 1000
                metrics_service_cls.get_instance().track_request(
                    provider="googleai",
                    status_code=error.status_code,
                    response_time=response_time,
                )
                return jsonify({"status": "error", "message": error.client_message}), (
                    401 if "authentication" in error.message.lower() else error.status_code
                )
            except Exception as error:
                logger.error("Unexpected error in Google chat completions: %s", error)
                response_time = (time.time() - start_time) * 1000
                metrics_service_cls.get_instance().track_request(
                    provider="googleai",
                    status_code=500,
                    response_time=response_time,
                )
                return jsonify(
                    {
                        "status": "error",
                        "message": f"Internal server error: {str(error)}",
                    }
                ), 500

        except APIError as error:
            logger.error("API Error in Google chat completions: %s", error.message)
            response_time = (time.time() - start_time) * 1000
            metrics_service_cls.get_instance().track_request(
                provider="googleai",
                status_code=error.status_code,
                response_time=response_time,
            )
            return jsonify({"status": "error", "message": error.client_message}), (
                401 if "authentication" in error.message.lower() else error.status_code
            )
        except Exception as error:
            logger.error("Unexpected error in Google chat completions: %s", error)
            response_time = (time.time() - start_time) * 1000
            metrics_service_cls.get_instance().track_request(
                provider="googleai",
                status_code=500,
                response_time=response_time,
            )
            return jsonify(
                {
                    "status": "error",
                    "message": f"Internal server error: {str(error)}",
                }
            ), 500
