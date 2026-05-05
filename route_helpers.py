import logging
import os
from functools import wraps
from typing import Any, Callable, Dict, Mapping, Optional

from flask import Response, g, jsonify, redirect, request, url_for

from config import Config
from services.auth_service import AuthService
from services.metrics_service import MetricsService
from services.rate_limit_service import RateLimitService

logger = logging.getLogger(__name__)

CORS_ALLOWED_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
CORS_DEFAULT_HEADERS = "Authorization, Content-Type, Accept, Origin, X-Requested-With"
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


def copy_upstream_response_headers(upstream_headers: Mapping[str, Any]) -> Dict[str, Any]:
    """Copy only response headers that are safe for Flask to emit downstream."""
    return {
        key: value
        for key, value in upstream_headers.items()
        if key.lower() not in HOP_BY_HOP_RESPONSE_HEADERS
    }


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


def is_api_request_path(path: str) -> bool:
    """
    Identify proxy/API paths that should participate in CORS handling.
    """
    stripped = path.strip("/")
    if not stripped:
        return False

    first_segment = stripped.split("/", 1)[0]
    return first_segment in Config.API_BASE_URLS or first_segment == "v1" or stripped in {"health", "healthz"}


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


def api_auth_required(func: Callable) -> Callable:
    """
    Decorator that checks if the request has a valid API key in
    the Authorization header (Bearer scheme).
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return build_cors_preflight_response()

        auth_header = request.headers.get("Authorization")
        logger.debug("Authorization header: %s", mask_authorization_header(auth_header))

        if not auth_header:
            logger.error("No Authorization header found")
            return jsonify(
                {
                    "error": "Authentication required",
                    "message": (
                        "Please provide your API key in the Authorization header. "
                        "Example: Authorization: Bearer YOUR_API_KEY"
                    ),
                }
            ), 401

        api_key = extract_bearer_token(auth_header)
        if not api_key:
            logger.error("Invalid Authorization header: %s", mask_authorization_header(auth_header))
            return jsonify(
                {
                    "error": "Invalid Authorization header",
                    "message": "Please use the Bearer authentication scheme.",
                }
            ), 401

        logger.debug("Extracted API key: %s", mask_secret(api_key))

        authenticated_user = AuthService.verify_api_key(api_key, request.remote_addr)
        if authenticated_user:
            logger.info(
                "Request authenticated with API key prefix %s for %s",
                authenticated_user.get("api_key_prefix"),
                authenticated_user.get("username"),
            )
            g.authenticated_user = authenticated_user

            payload_bytes = request.get_data(cache=True) or b""
            payload_json = request.get_json(silent=True) if request.is_json else None
            provider = provider_from_request_path(request.path, payload_json)
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

        logger.error("Invalid API key provided: %s", mask_secret(api_key))
        return jsonify(
            {
                "error": "Invalid API key",
                "message": "The provided API key is not valid",
            }
        ), 401

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
