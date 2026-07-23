import inspect
import logging
import re
from functools import wraps
from typing import Any, Callable, Dict, Mapping, Optional

from flask import Response, g, has_request_context, jsonify, redirect, request, url_for

from config import Config
from services.auth_service import AuthService
from services.metrics_service import MetricsService
from services.rate_limit_service import RateLimitService

logger = logging.getLogger(__name__)

CORS_ALLOWED_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
CORS_DEFAULT_HEADERS = (
    "Authorization, Content-Type, Accept, Origin, X-Requested-With, "
    "X-Api-Key, X-Goog-Api-Key, X-MultiLLM-Api-Key, Anthropic-Version, "
    "Anthropic-Beta, Anthropic-Dangerous-Direct-Browser-Access, "
    "Idempotency-Key, OpenAI-Beta, OpenAI-Organization, "
    "OpenAI-Project, Moderation, Moderation-Model, Redaction, X-App-Name, "
    "X-Billing-Mode, X-BYOK-Provider, X-Client-Request-ID, X-Encryption-Key, "
    "X-Encryption-Passphrase, X-Fal-Object-Lifecycle-Preference, X-PAYMENT, "
    "X-Prompt-Caching-Cut-After, X-Provider, X-Team-ID, X-Use-BYOK, x-x402"
)
CORS_EXPOSE_HEADERS = (
    "Retry-After, X-Request-ID, X-MultiLLM-Optimization, "
    "X-MultiLLM-Optimization-Mode, X-MultiLLM-Estimated-Input-Before, "
    "X-MultiLLM-Estimated-Input-After, X-MultiLLM-Image-Prompts-Compacted, "
    "X-MultiLLM-Messages-Summarized, X-MultiLLM-Optimization-Target-Met, "
    "X-MultiLLM-Summary, WWW-Authenticate, X-PAYMENT-RESPONSE, X-Poll-After, "
    "X-NanoGPT-Advisor-ID, X-NanoGPT-Data-Endpoint, "
    "X-NanoGPT-Direct-Endpoint, X-NanoGPT-Inline-Moderation-Cost-USD, "
    "X-NanoGPT-Inline-Moderation-Flagged, X-NanoGPT-Inline-Moderation-Model"
)
HOP_BY_HOP_RESPONSE_HEADERS = frozenset(
    {
        "connection",
        "content-encoding",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
RAW_PROVIDER_RESPONSE_HEADER_ALLOWLIST = frozenset(
    {
        "accept-ranges",
        "age",
        "cache-control",
        "content-disposition",
        "content-language",
        "content-range",
        "content-type",
        "etag",
        "expires",
        "last-modified",
        "openai-processing-ms",
        "openai-version",
        "request-id",
        "retry-after",
        "vary",
        "www-authenticate",
        "x-payment-response",
        "x-poll-after",
        "x-request-id",
        "x-should-retry",
    }
)
RAW_PROVIDER_RESPONSE_HEADER_PREFIXES = (
    "anthropic-ratelimit-",
    "ratelimit-",
    "x-fal-",
    "x-nanogpt-",
    "x-ratelimit-",
)


def copy_upstream_response_headers(upstream_headers: Mapping[str, Any]) -> Dict[str, Any]:
    """Copy only response headers that are safe for Flask to emit downstream."""
    return {
        key: value
        for key, value in upstream_headers.items()
        if key.lower() not in HOP_BY_HOP_RESPONSE_HEADERS
    }


def copy_raw_provider_response_headers(
    upstream_headers: Mapping[str, Any],
) -> Dict[str, Any]:
    """Copy the explicit response-header surface safe for raw API passthrough."""
    return {
        key: value
        for key, value in upstream_headers.items()
        if key.lower() in RAW_PROVIDER_RESPONSE_HEADER_ALLOWLIST
        or key.lower().startswith(RAW_PROVIDER_RESPONSE_HEADER_PREFIXES)
    }


def copy_linkapi_response_headers(upstream_headers: Mapping[str, Any]) -> Dict[str, Any]:
    """Backward-compatible alias for raw-provider response header filtering."""
    return copy_raw_provider_response_headers(upstream_headers)


def mask_secret(value: Optional[str]) -> str:
    """Return a short, non-sensitive representation of a secret value."""
    if not value:
        return "<missing>"
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def mask_authorization_header(value: Optional[str]) -> str:
    """Mask an Authorization header while preserving the scheme for debugging."""
    if not value:
        return "<missing>"
    scheme, separator, token = value.partition(" ")
    if not separator:
        return mask_secret(value)
    return f"{scheme} {mask_secret(token.strip())}"


def extract_bearer_token(value: Optional[str]) -> Optional[str]:
    """Extract a Bearer token using the HTTP auth scheme rules."""
    if not value:
        return None

    scheme, separator, token = value.partition(" ")
    if not separator or scheme.lower() != "bearer":
        return None

    token = token.strip()
    return token or None


def _provider_prefix(path: str) -> str:
    return path.strip("/").split("/", 1)[0].lower()


def _is_linkapi_request_path(path: str) -> bool:
    return _provider_prefix(path) == "linkapi"


def _accepts_native_api_key(path: str) -> bool:
    return _provider_prefix(path) in {"linkapi", "nanogpt", "navyai", "opencode"}


def request_api_key() -> Optional[str]:
    """Read the proxy credential without leaking native provider credentials upstream."""
    proxy_api_key = request.headers.get("X-MultiLLM-Api-Key")
    if proxy_api_key and proxy_api_key.strip():
        return proxy_api_key.strip()

    bearer_token = extract_bearer_token(request.headers.get("Authorization"))
    if bearer_token:
        return bearer_token

    if _accepts_native_api_key(request.path):
        api_key = request.headers.get("X-Api-Key")
        if api_key and api_key.strip():
            return api_key.strip()

    if _is_linkapi_request_path(request.path):
        for value in (
            request.headers.get("X-Goog-Api-Key"),
            request.args.get("key"),
        ):
            if value and value.strip():
                return value.strip()
    return None


def stream_upstream_response(upstream_response: Any) -> Response:
    """Stream an upstream entity body unchanged and release its connection."""

    raw_response = getattr(upstream_response, "raw", None)
    raw_read1 = getattr(raw_response, "read1", None)
    try:
        raw_read1_parameters = (
            inspect.signature(raw_read1).parameters if callable(raw_read1) else {}
        )
    except (TypeError, ValueError):
        raw_read1_parameters = {}
    closed = False

    def close_once() -> None:
        nonlocal closed
        if closed:
            return
        closed = True
        close = getattr(upstream_response, "close", None)
        if close is not None:
            if raw_response is None and hasattr(upstream_response, "_content_consumed"):
                upstream_response._content_consumed = True
            close()

    def generate():
        try:
            if raw_response is None:
                content = upstream_response.content
                if content:
                    yield content
            elif (
                upstream_response.headers.get("Content-Type", "")
                .partition(";")[0]
                .strip()
                .lower()
                == "text/event-stream"
                and callable(raw_read1)
                and "decode_content" in raw_read1_parameters
            ):
                while True:
                    chunk = raw_read1(64 * 1024, decode_content=True)
                    if not chunk:
                        break
                    yield chunk
            else:
                for chunk in upstream_response.iter_content(chunk_size=64 * 1024):
                    if chunk:
                        yield chunk
        finally:
            close_once()

    response_headers = copy_raw_provider_response_headers(upstream_response.headers)
    upstream_request_id = response_headers.get("X-Request-ID") or response_headers.get(
        "x-request-id"
    )
    if has_request_context() and upstream_request_id and re.fullmatch(
        r"[A-Za-z0-9_.:-]{1,128}",
        str(upstream_request_id),
    ):
        # The app's generic after-request hook emits g.request_id. Keep a safe
        # upstream OpenAI request ID intact for support and billing correlation.
        g.request_id = str(upstream_request_id)

    response = Response(
        generate(),
        status=upstream_response.status_code,
        headers=response_headers,
    )
    response.call_on_close(close_once)
    return response


def is_api_request_path(path: str) -> bool:
    """
    Identify proxy/API paths that should participate in CORS handling.
    """
    stripped = path.strip("/")
    if not stripped:
        return False

    first_segment = stripped.split("/", 1)[0]
    return (
        first_segment in Config.API_BASE_URLS
        or first_segment in {"optimize", "v1"}
        or stripped in {"health", "healthz"}
    )


def provider_from_request_path(path: str, payload_json: Optional[Dict[str, Any]] = None) -> str:
    first_segment = path.strip("/").split("/", 1)[0]
    if first_segment == "v1" and isinstance(payload_json, dict):
        model = payload_json.get("model")
        if isinstance(model, str) and ":" in model:
            provider = model.split(":", 1)[0].strip().lower()
            if provider:
                return provider
        return "unified"
    return first_segment


def apply_cors_headers(response: Response, origin: Optional[str] = None) -> Response:
    """
    Add CORS headers for browser origins on API routes.
    """
    request_origin = origin or request.headers.get("Origin")
    if not request_origin or not is_api_request_path(request.path):
        return response

    response.headers["Access-Control-Allow-Origin"] = request_origin
    response.headers["Access-Control-Allow-Methods"] = CORS_ALLOWED_METHODS
    response.headers["Access-Control-Allow-Headers"] = request.headers.get(
        "Access-Control-Request-Headers",
        CORS_DEFAULT_HEADERS,
    )
    response.headers["Access-Control-Expose-Headers"] = CORS_EXPOSE_HEADERS
    response.headers["Access-Control-Max-Age"] = "86400"

    vary = response.headers.get("Vary")
    response.headers["Vary"] = f"{vary}, Origin" if vary else "Origin"
    return response


def build_cors_preflight_response(origin: Optional[str] = None) -> Response:
    """
    Return a preflight response for browser API calls.
    """
    response = Response(status=204)
    return apply_cors_headers(response, origin=origin)


def login_required(func: Callable) -> Callable:
    """
    Decorator that checks if the user is authenticated.
    Redirects to the login page if not authenticated.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not AuthService.is_authenticated():
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapper


def _authenticate_api_request():
    """Authenticate the proxy caller and return an error response on failure."""
    auth_header = request.headers.get("Authorization")
    logger.debug("Authorization header: %s", mask_authorization_header(auth_header))

    api_key = request_api_key()
    if not api_key:
        if auth_header:
            logger.error(
                "Invalid Authorization header: %s",
                mask_authorization_header(auth_header),
            )
            return jsonify(
                {
                    "error": "Invalid Authorization header",
                    "message": "Please use the Bearer authentication scheme.",
                }
            ), 401

        logger.error("No proxy API credential found")
        provider_prefix = _provider_prefix(request.path)
        if provider_prefix == "linkapi":
            native_hint = (
                " Native LinkAPI clients may also use X-Api-Key, "
                "X-Goog-Api-Key, or the Gemini key query parameter."
            )
        elif provider_prefix in {"nanogpt", "navyai", "opencode"}:
            native_hint = " Native Anthropic clients may also use X-Api-Key."
        else:
            native_hint = ""
        return jsonify(
            {
                "error": "Authentication required",
                "message": (
                    "Please provide your API key in the Authorization header "
                    "or X-MultiLLM-Api-Key. "
                    f"Example: Authorization: Bearer YOUR_API_KEY{native_hint}"
                ),
            }
        ), 401

    logger.debug("Extracted API key: %s", mask_secret(api_key))
    authenticated_user = AuthService.verify_api_key(api_key, request.remote_addr)
    if not authenticated_user:
        logger.error("Invalid API key provided: %s", mask_secret(api_key))
        return jsonify(
            {
                "error": "Invalid API key",
                "message": "The provided API key is not valid",
            }
        ), 401

    logger.info(
        "Request authenticated with API key prefix %s for %s",
        authenticated_user.get("api_key_prefix"),
        authenticated_user.get("username"),
    )
    g.authenticated_user = authenticated_user
    return None


def api_authenticate_only(func: Callable) -> Callable:
    """Authenticate a proxy request without reserving a rate-limit slot."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return build_cors_preflight_response()

        authentication_error = _authenticate_api_request()
        if authentication_error is not None:
            return authentication_error
        return func(*args, **kwargs)

    return wrapper


def api_auth_required(func: Callable) -> Callable:
    """Authenticate a proxy request and reserve its provider rate budget."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return build_cors_preflight_response()

        authentication_error = _authenticate_api_request()
        if authentication_error is not None:
            return authentication_error

        payload_bytes = request.get_data(cache=True) or b""
        payload_json = request.get_json(silent=True) if request.is_json else None
        provider = provider_from_request_path(request.path, payload_json)
        authenticated_user = g.authenticated_user
        limit_decision = RateLimitService.enforce_request(
            provider=provider,
            user=authenticated_user,
            payload_bytes=payload_bytes,
            payload_json=payload_json,
            remote_addr=request.remote_addr,
        )
        g.rate_limit = limit_decision.metadata
        if not limit_decision.allowed:
            response = jsonify(
                {
                    "error": limit_decision.error,
                    "message": limit_decision.message,
                }
            )
            if limit_decision.retry_after:
                response.headers["Retry-After"] = str(limit_decision.retry_after)
            return response, limit_decision.status_code
        return func(*args, **kwargs)

    return wrapper


def check_provider(provider: str, details: Dict[str, Any], app_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check the status of a provider by retrieving stats and verifying tokens.
    """
    metrics_service = MetricsService.get_instance()
    provider_stats = {}
    try:
        provider_stats = metrics_service.get_provider_stats(provider)
    except Exception as error:
        logger.error("Error fetching provider stats for %s: %s", provider, error)

    base_payload = {
        "name": provider.upper(),
        "description": details.get("description", ""),
        "endpoints": details.get("endpoints", []),
        "requests_24h": provider_stats.get("requests_24h", 0),
        "success_rate": provider_stats.get("success_rate", 0),
        "error_rate": provider_stats.get("error_rate", 0),
        "errors": provider_stats.get("errors", 0),
        "avg_latency": provider_stats.get("avg_latency", 0),
        "p95_latency": provider_stats.get("p95_latency", 0),
        "last_request_at": provider_stats.get("last_request_at"),
        "example_curl": details.get("example_curl", ""),
    }

    try:
        if provider == "googleai":
            token = AuthService.get_google_token()
            if not token:
                return {
                    **base_payload,
                    "active": False,
                    "is_configured": False,
                    "status": "error",
                    "error": "Google AI token not configured",
                }
            return {
                **base_payload,
                "active": True,
                "is_configured": True,
                "status": "ok",
            }

        api_key = AuthService.get_api_key(provider)
        if not api_key:
            return {
                **base_payload,
                "active": False,
                "is_configured": False,
                "status": "error",
                "error": f"{provider.upper()} API key not configured",
            }
        return {
            **base_payload,
            "active": True,
            "is_configured": True,
            "status": "ok",
        }
    except Exception as error:
        logger.error("Error checking provider %s: %s", provider, error)
        return {
            **base_payload,
            "active": False,
            "is_configured": False,
            "status": "error",
            "error": str(error),
        }
