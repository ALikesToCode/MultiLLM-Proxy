import logging
import os

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from config import Config, DevelopmentConfig, ProductionConfig
from env_loader import load_runtime_env
from error_handlers import init_error_handlers
from route_helpers import (
    api_auth_required,
    apply_cors_headers,
    build_cors_preflight_response,
    check_provider,
    is_api_request_path,
    login_required,
)
from routes.core import register_core_routes
from routes.proxy import register_proxy_routes
from routes.unified import register_unified_routes
from security_config import validate_runtime_secrets
from services.auth_service import AuthService
from services.cache_service import CacheService
from services.metrics_service import MetricsService
from services.proxy_service import ProxyService

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """
    Create and configure the Flask application.
    """
    load_runtime_env()
    runtime_secrets = validate_runtime_secrets()

    app = Flask(
        __name__,
        static_url_path="/static",
        template_folder="templates",
    )
    app.secret_key = runtime_secrets["FLASK_SECRET_KEY"]
    app.config["JWT_SECRET"] = runtime_secrets["JWT_SECRET"]

    csrf = CSRFProtect()
    csrf.init_app(app)

    for directory in ["static", "templates"]:
        dir_path = os.path.join(os.path.dirname(__file__), directory)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

    flask_env = os.environ.get("FLASK_ENV", "production")
    app.config.from_object(Config)
    if flask_env == "development":
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = flask_env != "development"

    init_error_handlers(app)
    AuthService.initialize()

    register_proxy_routes(app, csrf, AuthService, MetricsService, ProxyService)
    register_unified_routes(app, csrf, AuthService, MetricsService, ProxyService)
    register_core_routes(app)

    return app


app = create_app()


if __name__ == "__main__":
    try:
        port = int(os.environ.get("SERVER_PORT", Config.DEFAULT_PORT))
        host = os.environ.get("SERVER_HOST", "0.0.0.0")
        logger.info("Starting server on %s:%s", host, port)
        app.run(
            host=host,
            port=port,
            threaded=True,
            use_reloader=False,
            debug=False,
        )
    except Exception as error:
        logger.error("Server failed to start: %s", error)
        raise
