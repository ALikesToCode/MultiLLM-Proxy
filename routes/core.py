import json
import logging
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import psutil
from flask import Response, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from flask_wtf.csrf import CSRFError

from config import Config
from error_handlers import APIError, INTERNAL_ERROR_MESSAGE, get_request_id, internal_error_payload
from proxy import PROVIDER_DETAILS
from route_helpers import apply_cors_headers, check_provider, copy_upstream_response_headers, login_required
from services.auth_service import AuthService
from services.metrics_service import MetricsService
from services.proxy_service import ProxyService

logger = logging.getLogger(__name__)

TRUE_JSON_VALUES = {"1", "true", "yes", "on"}
FALSE_JSON_VALUES = {"", "0", "false", "no", "off"}
PRIVATE_CACHE_ENDPOINTS = {
    "login",
    "logout",
    "manage_users",
    "delete_user",
    "rotate_api_key",
    "status_page",
    "openrouter_dashboard",
    "admin_request_metrics",
    "dashboard_openrouter_chat_completions",
    "dashboard_openrouter_credits",
    "list_admin_models",
    "disable_admin_model",
    "status_updates",
}


def parse_json_bool(value, field_name: str) -> bool:
    """Parse JSON boolean-ish values without treating arbitrary strings as true."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in TRUE_JSON_VALUES:
            return True
        if normalized in FALSE_JSON_VALUES:
            return False
    raise APIError(f"{field_name} must be a boolean", status_code=400)


def is_safe_redirect_target(target: str | None) -> bool:
    """Allow only local, absolute-path redirects after login."""
    if not target:
        return False

    parsed = urlsplit(target)
    return (
        not parsed.scheme
        and not parsed.netloc
        and target.startswith("/")
        and not target.startswith("//")
        and "\\" not in target
    )


def build_system_metrics(metrics_service: MetricsService) -> dict:
    """Collect system metrics used by the dashboard and SSE stream."""
    return {
        "cpu_usage": round(psutil.cpu_percent(interval=None), 1),
        "memory_usage": round(psutil.virtual_memory().percent, 1),
        "start_time": metrics_service.start_time,
        "uptime_start_seconds": int(metrics_service.start_time),
    }


def build_dashboard_analytics(metrics_service: MetricsService, providers: dict, stats: dict | None = None) -> dict:
    """Assemble dashboard-focused analytics derived from request and provider data."""
    stats = stats or metrics_service.get_stats()
    provider_breakdown = metrics_service.get_provider_breakdown()
    recent_failures = metrics_service.get_recent_failures(limit=6)

    configured_providers = sum(
        1 for details in providers.values()
        if details.get("is_configured", details.get("active", False))
    )
    active_providers = sum(1 for details in providers.values() if details.get("active"))

    traffic_series = stats.get("traffic_series", [])
    peak_hour = max(traffic_series, key=lambda item: item.get("requests", 0), default=None)

    return {
        "provider_breakdown": provider_breakdown,
        "recent_failures": recent_failures,
        "configured_providers": configured_providers,
        "active_providers": active_providers,
        "inactive_providers": max(configured_providers - active_providers, 0),
        "providers_with_traffic": len(provider_breakdown),
        "peak_hour": peak_hour,
    }


def require_admin_dashboard_user() -> dict:
    """Return the current admin user or raise a client-safe API error."""
    current_user = AuthService.get_current_user()
    if not current_user or not current_user.get("is_admin", False):
        raise APIError("Only admin users can perform this action", status_code=403)
    return current_user


def build_openrouter_dashboard_headers() -> dict:
    """Build provider headers for dashboard BFF requests without exposing keys to browsers."""
    api_key = AuthService.get_api_key("openrouter")
    if not api_key:
        raise APIError("OpenRouter API key is not configured", status_code=500)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    site_url = os.environ.get("OPENROUTER_SITE_URL")
    app_name = os.environ.get("OPENROUTER_APP_NAME")
    if site_url:
        headers["HTTP-Referer"] = site_url
    if app_name:
        headers["X-OpenRouter-Title"] = app_name

    return headers


def apply_private_cache_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def register_core_routes(app) -> None:
    @app.errorhandler(CSRFError)
    def handle_csrf_error(error: CSRFError):
        """
        Handle CSRF errors, returning JSON if it's an AJAX/JSON request.
        """
        error_msg = f"CSRF token missing or invalid: {str(error)}"
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"error": "CSRF token missing or invalid", "message": error_msg}), 400
        return render_template("error.html", error=error_msg), 400

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """
        Handle user login. On POST, authenticate with username+api_key.
        On GET, render the login template.
        """
        try:
            if request.method == "POST":
                username = request.form.get("username")
                api_key = request.form.get("api_key")
                if AuthService.authenticate_user(username, api_key):
                    next_page = request.args.get("next")
                    if is_safe_redirect_target(next_page):
                        return redirect(next_page)
                    return redirect(url_for("status_page"))
                return render_template("login.html", error="Invalid username or API key")

            logger.info("Rendering login template")
            return render_template(
                "login.html",
                error=None,
                config={
                    "server_url": Config.SERVER_BASE_URL,
                    "providers": list(Config.API_BASE_URLS.keys()),
                },
            )
        except Exception as error:
            logger.exception("Error in login route")
            error_msg = f"Login error: {str(error)}"
            if request.method == "GET":
                try:
                    return render_template("login.html", error=error_msg)
                except Exception as inner_error:
                    logger.exception("Error rendering basic login template")
                    return f"Critical error: {str(inner_error)}", 500
            return jsonify({"error": error_msg}), 500

    @app.route("/logout")
    def logout():
        """
        Handle user logout.
        """
        AuthService.logout()
        return redirect(url_for("login"))

    @app.route("/users", methods=["GET", "POST"])
    @login_required
    def manage_users():
        """
        User management page. GET returns list of users (JSON or HTML).
        POST creates a new user (admin only).
        """
        try:
            if request.method == "POST":
                current_user = AuthService.get_current_user()
                if not current_user or not current_user.get("is_admin", False):
                    raise APIError("Only admin users can create new users", status_code=403)

                payload = request.get_json(silent=True) or {}
                username = payload.get("username") or request.form.get("username")
                is_admin = (
                    parse_json_bool(payload.get("is_admin"), "is_admin")
                    if payload
                    else request.form.get("is_admin") == "on"
                )

                if not username:
                    raise APIError("Username is required", status_code=400)

                user = AuthService.create_user(username, is_admin)
                return jsonify(
                    {
                        "status": "success",
                        "message": "User created successfully",
                        "user": user,
                    }
                )

            users = AuthService.list_users()
            if "application/json" in request.headers.get("Accept", ""):
                return jsonify({"status": "success", "users": users})
            return render_template(
                "users.html",
                users=users,
                current_user=AuthService.get_current_user(),
            )

        except APIError as error:
            status_code = error.status_code
            if "application/json" in request.headers.get("Accept", ""):
                return jsonify({"status": "error", "message": error.client_message}), status_code
            return render_template("error.html", error=error.client_message), status_code

        except Exception as error:
            logger.error("Error in user management: %s", error)
            if "application/json" in request.headers.get("Accept", ""):
                return jsonify({"status": "error", "message": str(error)}), 500
            return render_template("500.html", error=str(error)), 500

    @app.route("/users/<username>", methods=["DELETE"])
    @login_required
    def delete_user(username: str):
        """
        Delete a user by username.
        """
        try:
            AuthService.delete_user(username)
            return jsonify({"message": f"User {username} deleted successfully"})
        except APIError as error:
            return jsonify({"error": str(error)}), error.status_code

    @app.route("/users/<username>/rotate-key", methods=["POST"])
    @login_required
    def rotate_api_key(username: str):
        """
        Generate a new API key for a given user.
        """
        try:
            result = AuthService.rotate_api_key(username)
            return jsonify(result)
        except APIError as error:
            return jsonify({"error": str(error)}), error.status_code

    @app.route("/favicon.ico")
    def favicon():
        """
        Serve favicon
        """
        return send_from_directory(
            os.path.join(app.root_path, "static"),
            "favicon.ico",
            mimetype="image/vnd.microsoft.icon",
        )

    @app.route("/manifest.webmanifest")
    def web_manifest():
        """
        Serve the PWA web manifest from the app root.
        """
        manifest_path = Path(app.root_path) / "static" / "manifest.webmanifest"
        response = Response(manifest_path.read_bytes(), mimetype="application/manifest+json")
        response.headers["Cache-Control"] = "public, max-age=300"
        return response

    @app.route("/service-worker.js")
    def service_worker():
        """
        Serve the PWA service worker from the app root so it can control the whole app.
        """
        service_worker_path = Path(app.root_path) / "static" / "service-worker.js"
        response = Response(service_worker_path.read_bytes(), mimetype="application/javascript")
        response.headers["Service-Worker-Allowed"] = "/"
        response.headers["Cache-Control"] = "no-cache"
        return response

    @app.route("/apple-touch-icon.png")
    def apple_touch_icon():
        """
        Serve the iOS home screen icon from the app root.
        """
        return send_from_directory(
            os.path.join(app.root_path, "static", "icons"),
            "apple-touch-icon.png",
            mimetype="image/png",
        )

    @app.route("/static/<path:filename>")
    def static_files(filename: str):
        """
        Serve static files
        """
        response = send_from_directory("static", filename)
        response.headers.setdefault("Cache-Control", "public, max-age=3600")
        return response

    @app.before_request
    def handle_redirects():
        """
        For every request (except login, static, favicon), enforce authentication.
        Also handle direct requests to /<provider> endpoints.
        """
        if request.method == "OPTIONS":
            return None

        if request.headers.get("Authorization"):
            return None

        if request.endpoint in [
            "login",
            "static_files",
            "favicon",
            "health_check",
            "web_manifest",
            "service_worker",
            "apple_touch_icon",
        ] or request.path.startswith("/static/"):
            return None

        if not AuthService.is_authenticated():
            if request.path == "/":
                return redirect(url_for("login"))
            if request.is_json:
                raise APIError("Authentication required", status_code=401)
            return redirect(url_for("login", next=request.url))

        sanitized_path = request.path.rstrip("/")
        if sanitized_path in [f"/{prov}" for prov in app.config["API_BASE_URLS"]]:
            return app.view_functions["proxy"](sanitized_path.strip("/"))

        return None

    @app.after_request
    def add_response_headers(response):
        """
        Attach CORS and conservative cache headers.
        """
        response = apply_cors_headers(response)

        if request.endpoint in {"static_files", "favicon", "apple_touch_icon"}:
            response.headers["Cache-Control"] = "public, max-age=3600"
            return response
        if request.endpoint == "web_manifest":
            response.headers.setdefault("Cache-Control", "public, max-age=300")
            return response

        if (
            request.endpoint in PRIVATE_CACHE_ENDPOINTS
            or request.endpoint in {"health_check"}
            or request.headers.get("Authorization")
            or AuthService.is_authenticated()
        ):
            apply_private_cache_headers(response)

        return response

    @app.route("/health")
    @app.route("/healthz")
    def health_check():
        """
        Health check endpoint.
        """
        try:
            response = jsonify(
                {
                    "status": "healthy",
                    "config": {
                        "host": os.environ.get("SERVER_HOST", Config.DEFAULT_HOST),
                        "port": int(os.environ.get("SERVER_PORT", Config.DEFAULT_PORT)),
                    },
                }
            )
            response.headers["Cache-Control"] = "no-store"
            return response, 200
        except Exception as error:
            logger.error("Health check failed: %s", error)
            return jsonify({"status": "error", "message": str(error)}), 500

    @app.route("/")
    @login_required
    def status_page():
        """
        A status page showing available providers, system metrics, etc.
        """
        try:
            providers = {}
            errors = []

            metrics_service = MetricsService.get_instance()
            system = build_system_metrics(metrics_service)

            stats = metrics_service.get_stats()
            users_info = {
                "total": AuthService.count_users(),
                "active_sessions": len(session.keys()) if session else 1,
                "recent_activity": len(metrics_service.get_recent_activity()),
            }

            for provider, details in PROVIDER_DETAILS.items():
                try:
                    providers[provider] = check_provider(provider, details, app.config)
                except Exception as error:
                    logger.error("Failed to check %s: %s", provider, error)
                    errors.append(f"Failed to check {provider}: {str(error)}")
                    providers[provider] = {
                        "name": provider.upper(),
                        "active": False,
                        "is_configured": False,
                        "status": "error",
                        "error": str(error),
                        "requests_24h": 0,
                        "success_rate": 0,
                        "error_rate": 0,
                        "errors": 0,
                        "avg_latency": 0,
                        "p95_latency": 0,
                        "last_request_at": None,
                    }

            recent_activity = metrics_service.get_recent_activity()
            analytics = build_dashboard_analytics(metrics_service, providers, stats)

            if "application/json" in request.headers.get("Accept", ""):
                return jsonify(
                    {
                        "status": "running",
                        "system": system,
                        "stats": stats,
                        "analytics": analytics,
                        "users": users_info,
                        "providers": providers,
                        "recent_activity": recent_activity,
                        "errors": errors if errors else None,
                        "user": AuthService.get_current_user(),
                    }
                )
            return render_template(
                "status.html",
                system=system,
                stats=stats,
                analytics=analytics,
                users=users_info,
                providers=providers,
                recent_activity=recent_activity,
                errors=errors if errors else None,
                user=AuthService.get_current_user(),
            )
        except Exception as error:
            logger.error("Status page error: %s", error)
            if "application/json" in request.headers.get("Accept", ""):
                return jsonify({"status": "error", "message": str(error)}), 500
            return render_template("500.html", error=str(error)), 500

    @app.route("/openrouter")
    @login_required
    def openrouter_dashboard():
        """
        OpenRouter dashboard for testing and interacting with OpenRouter models.
        """
        try:
            return render_template("openrouter.html", user=AuthService.get_current_user())
        except Exception as error:
            logger.error("OpenRouter dashboard error: %s", error)
            if "application/json" in request.headers.get("Accept", ""):
                return jsonify({"status": "error", "message": str(error)}), 500
            return render_template("500.html", error=str(error)), 500

    @app.route("/admin/metrics/requests")
    @login_required
    def admin_request_metrics():
        require_admin_dashboard_user()
        try:
            limit = max(1, min(int(request.args.get("limit", 100)), 500))
        except ValueError:
            limit = 100
        return jsonify(
            {
                "requests": MetricsService.get_instance().get_request_records(limit=limit),
            }
        )

    @app.route("/dashboard/openrouter/chat-completions", methods=["POST"])
    @login_required
    def dashboard_openrouter_chat_completions():
        """
        Server-side dashboard proxy for OpenRouter chat completions.
        Browser clients authenticate with the Flask session and never receive provider keys.
        """
        require_admin_dashboard_user()
        payload = request.get_json(silent=True) or {}
        if not payload.get("model"):
            raise APIError("Model is required", status_code=400)
        if not isinstance(payload.get("messages"), list) or not payload["messages"]:
            raise APIError("At least one message is required", status_code=400)

        start_time = time.time()
        is_streaming = bool(payload.get("stream", False))
        headers = build_openrouter_dashboard_headers()
        if is_streaming:
            headers["Accept"] = "text/event-stream"

        try:
            upstream_response = ProxyService.make_request(
                method="POST",
                url="https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                params=request.args,
                data=json.dumps(payload).encode("utf-8"),
                api_provider="openrouter",
                use_cache=False,
            )
            MetricsService.get_instance().track_request(
                provider="openrouter",
                status_code=upstream_response.status_code,
                response_time=(time.time() - start_time) * 1000,
            )

            if isinstance(upstream_response, Response):
                return upstream_response

            return Response(
                upstream_response.content,
                status=upstream_response.status_code,
                headers=copy_upstream_response_headers(upstream_response.headers),
                content_type=upstream_response.headers.get("Content-Type", "application/json"),
            )
        except Exception as error:
            status_code = error.status_code if isinstance(error, APIError) else 502
            MetricsService.get_instance().track_request(
                provider="openrouter",
                status_code=status_code,
                response_time=(time.time() - start_time) * 1000,
            )
            raise

    @app.route("/dashboard/openrouter/credits", methods=["GET"])
    @login_required
    def dashboard_openrouter_credits():
        """
        Server-side OpenRouter credit lookup for the dashboard.
        """
        require_admin_dashboard_user()
        start_time = time.time()
        try:
            upstream_response = ProxyService.make_request(
                method="GET",
                url="https://openrouter.ai/api/v1/key",
                headers=build_openrouter_dashboard_headers(),
                params=request.args,
                data=None,
                api_provider="openrouter",
                use_cache=False,
            )
            MetricsService.get_instance().track_request(
                provider="openrouter",
                status_code=upstream_response.status_code,
                response_time=(time.time() - start_time) * 1000,
            )
            return Response(
                upstream_response.content,
                status=upstream_response.status_code,
                headers=copy_upstream_response_headers(upstream_response.headers),
                content_type=upstream_response.headers.get("Content-Type", "application/json"),
            )
        except Exception as error:
            status_code = error.status_code if isinstance(error, APIError) else 502
            MetricsService.get_instance().track_request(
                provider="openrouter",
                status_code=status_code,
                response_time=(time.time() - start_time) * 1000,
            )
            raise

    @app.errorhandler(404)
    def not_found_error(error):
        """
        Handle 404 errors.
        """
        if request.path == "/favicon.ico":
            return send_from_directory("static", "favicon.ico")
        return render_template("404.html", request_id=get_request_id()), 404

    @app.errorhandler(500)
    def internal_error(error):
        """
        Handle 500 errors.
        """
        request_id = get_request_id()
        logger.exception("Internal server error request_id=%s", request_id)
        if request.is_json or "application/json" in request.headers.get("Accept", ""):
            return jsonify(internal_error_payload()), 500
        return render_template(
            "500.html",
            error=INTERNAL_ERROR_MESSAGE,
            request_id=request_id,
        ), 500

    @app.route("/status/updates")
    @login_required
    def status_updates():
        """
        Server-Sent Events endpoint for real-time status updates.
        Streams system, stats, and providers info.
        """

        def generate_updates():
            metrics_service = MetricsService.get_instance()

            while True:
                current_time = int(time.time())
                try:
                    if current_time % 5 == 0:
                        system_data = build_system_metrics(metrics_service)
                        yield f"event: system\ndata: {json.dumps(system_data)}\n\n"

                    if current_time % 10 == 0:
                        stats_data = metrics_service.get_stats()
                        yield f"event: stats\ndata: {json.dumps(stats_data)}\n\n"

                    if current_time % 3 == 0:
                        recent_activity = metrics_service.get_recent_activity()
                        yield f"event: activity\ndata: {json.dumps(recent_activity)}\n\n"

                    if current_time % 30 == 0:
                        providers_info = {}
                        for provider, details in PROVIDER_DETAILS.items():
                            try:
                                providers_info[provider] = check_provider(provider, details, app.config)
                            except Exception as error:
                                logger.error("Error checking provider %s: %s", provider, error)
                                providers_info[provider] = {
                                    "active": False,
                                    "is_configured": False,
                                    "status": "error",
                                    "error": str(error),
                                    "requests_24h": 0,
                                    "success_rate": 0,
                                    "error_rate": 0,
                                    "errors": 0,
                                    "avg_latency": 0,
                                    "p95_latency": 0,
                                    "last_request_at": None,
                                }
                        yield f"event: providers\ndata: {json.dumps(providers_info)}\n\n"
                        analytics_data = build_dashboard_analytics(
                            metrics_service,
                            providers_info,
                            stats=metrics_service.get_stats(),
                        )
                        yield f"event: analytics\ndata: {json.dumps(analytics_data)}\n\n"

                    time.sleep(1)

                except GeneratorExit:
                    break
                except Exception as error:
                    logger.error("Error generating status updates: %s", error)
                    yield f"event: error\ndata: {json.dumps({'error': str(error)})}\n\n"
                    time.sleep(5)

        return Response(
            generate_updates(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )
