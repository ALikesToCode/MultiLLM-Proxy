import logging
import os
from functools import wraps
from typing import Any, Callable, Dict, Optional

from flask import Response, jsonify, redirect, request, url_for

from config import Config
from services.auth_service import AuthService
from services.metrics_service import MetricsService

logger = logging.getLogger(__name__)

CORS_ALLOWED_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
CORS_DEFAULT_HEADERS = "Authorization, Content-Type, Accept, Origin, X-Requested-With"


def is_api_request_path(path: str) -> bool:
    """
    Identify proxy/API paths that should participate in CORS handling.
    """
    stripped = path.strip("/")
    if not stripped:
        return False

    first_segment = stripped.split("/", 1)[0]
    return first_segment in Config.API_BASE_URLS or stripped == "health"


def apply_cors_headers(response: Response, origin: Optional[str] = None) -> Response:
    """
    Add permissive CORS headers for API routes when a browser origin is present.
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
    Return a 204 preflight response for browser API calls.
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
        logger.debug("Raw Authorization header: %s", auth_header)

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

        api_key = auth_header.replace("Bearer ", "").strip()
        logger.debug("Extracted API key: %s...", api_key[:5])

        admin_api_key = os.environ.get("ADMIN_API_KEY")
        if not admin_api_key:
            logger.error("ADMIN_API_KEY not configured in environment")
            return jsonify(
                {
                    "error": "Server configuration error",
                    "message": "ADMIN_API_KEY not configured on server",
                }
            ), 500

        logger.debug("Admin key first 5 chars: %s...", admin_api_key[:5])
        if api_key == admin_api_key:
            logger.info("Request authenticated with admin API key")
            return func(*args, **kwargs)

        for username, user_data in AuthService._users.items():
            user_api_key = user_data.get("api_key")
            if user_api_key and user_api_key == api_key:
                logger.info("Request authenticated with user API key for %s", username)
                return func(*args, **kwargs)

        logger.error("Invalid API key provided: %s...", api_key[:5])
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

    try:
        if provider == "googleai":
            token = AuthService.get_google_token()
            if not token:
                return {
                    "name": provider.upper(),
                    "description": details.get("description", ""),
                    "active": False,
                    "is_configured": False,
                    "endpoints": details.get("endpoints", []),
                    "status": "error",
                    "error": "Google AI token not configured",
                    "requests_24h": provider_stats.get("requests_24h", 0),
                    "success_rate": provider_stats.get("success_rate", 0),
                    "avg_latency": provider_stats.get("avg_latency", 0),
                    "example_curl": details.get("example_curl", ""),
                }
            return {
                "name": provider.upper(),
                "description": details.get("description", ""),
                "active": True,
                "is_configured": True,
                "endpoints": details.get("endpoints", []),
                "status": "ok",
                "requests_24h": provider_stats.get("requests_24h", 0),
                "success_rate": provider_stats.get("success_rate", 0),
                "avg_latency": provider_stats.get("avg_latency", 0),
                "example_curl": details.get("example_curl", ""),
            }

        api_key = AuthService.get_api_key(provider)
        if not api_key:
            return {
                "name": provider.upper(),
                "description": details.get("description", ""),
                "active": False,
                "is_configured": False,
                "endpoints": details.get("endpoints", []),
                "status": "error",
                "error": f"{provider.upper()} API key not configured",
                "requests_24h": provider_stats.get("requests_24h", 0),
                "success_rate": provider_stats.get("success_rate", 0),
                "avg_latency": provider_stats.get("avg_latency", 0),
                "example_curl": details.get("example_curl", ""),
            }
        return {
            "name": provider.upper(),
            "description": details.get("description", ""),
            "active": True,
            "is_configured": True,
            "endpoints": details.get("endpoints", []),
            "status": "ok",
            "requests_24h": provider_stats.get("requests_24h", 0),
            "success_rate": provider_stats.get("success_rate", 0),
            "avg_latency": provider_stats.get("avg_latency", 0),
            "example_curl": details.get("example_curl", ""),
        }
    except Exception as error:
        logger.error("Error checking provider %s: %s", provider, error)
        return {
            "name": provider.upper(),
            "description": details.get("description", ""),
            "active": False,
            "is_configured": False,
            "endpoints": details.get("endpoints", []),
            "status": "error",
            "error": str(error),
            "requests_24h": provider_stats.get("requests_24h", 0),
            "success_rate": provider_stats.get("success_rate", 0),
            "avg_latency": provider_stats.get("avg_latency", 0),
            "example_curl": details.get("example_curl", ""),
        }
