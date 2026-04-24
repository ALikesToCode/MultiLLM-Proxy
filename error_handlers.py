import logging
import re
import secrets

from flask import g, jsonify, render_template, request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

INTERNAL_ERROR_MESSAGE = "An unexpected error occurred."
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class APIError(Exception):
    def __init__(self, message, status_code=500, payload=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.payload = payload

    @property
    def client_message(self):
        if self.status_code >= 500:
            return INTERNAL_ERROR_MESSAGE
        return self.message

    def __str__(self):
        return self.client_message

    def to_dict(self):
        rv = dict(self.payload or ())
        if self.status_code >= 500:
            rv.setdefault("error", "internal_error")
            rv["message"] = INTERNAL_ERROR_MESSAGE
        else:
            rv["message"] = self.message
        rv["request_id"] = get_request_id()
        return rv


def get_request_id():
    request_id = getattr(g, "request_id", None)
    if request_id:
        return request_id
    request_id = f"req_{secrets.token_urlsafe(12)}"
    g.request_id = request_id
    return request_id


def _select_request_id():
    incoming = (request.headers.get("X-Request-ID") or "").strip()
    if REQUEST_ID_PATTERN.fullmatch(incoming):
        return incoming
    return f"req_{secrets.token_urlsafe(12)}"


def _wants_json_response():
    return request.is_json or "application/json" in request.headers.get("Accept", "")


def internal_error_payload():
    return {
        "error": "internal_error",
        "message": INTERNAL_ERROR_MESSAGE,
        "request_id": get_request_id(),
    }


def init_error_handlers(app):
    @app.before_request
    def attach_request_id():
        g.request_id = _select_request_id()

    @app.after_request
    def add_request_id_header(response):
        response.headers["X-Request-ID"] = get_request_id()
        return response

    @app.errorhandler(APIError)
    def handle_api_error(error):
        """Handle API errors without full traceback"""
        request_id = get_request_id()
        if error.status_code >= 500:
            logger.error(
                "API Error request_id=%s status=%s message=%s",
                request_id,
                error.status_code,
                error.message,
                exc_info=True,
            )
        else:
            logger.warning(
                "API Error request_id=%s status=%s message=%s",
                request_id,
                error.status_code,
                error.message,
            )
        if _wants_json_response():
            response = jsonify(error.to_dict())
            response.status_code = error.status_code
            return response
        return render_template(
            "error.html",
            error=error.client_message,
            request_id=request_id,
        ), error.status_code

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        """Handle unexpected errors without full traceback"""
        request_id = get_request_id()
        logger.exception("Unexpected error request_id=%s", request_id)
        
        if _wants_json_response():
            return jsonify(internal_error_payload()), 500
        return render_template(
            "error.html",
            error=INTERNAL_ERROR_MESSAGE,
            request_id=request_id,
        ), 500

    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 errors"""
        if request.path == '/favicon.ico':
            return app.send_static_file('favicon.ico')
            
        if _wants_json_response():
            return jsonify({"error": "Not found", "request_id": get_request_id()}), 404
        return render_template('error.html', error="Page not found"), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 errors without recursion"""
        request_id = get_request_id()
        logger.exception("Internal server error request_id=%s", request_id)
        
        if _wants_json_response():
            return jsonify(internal_error_payload()), 500
        return render_template(
            "error.html",
            error=INTERNAL_ERROR_MESSAGE,
            request_id=request_id,
        ), 500
