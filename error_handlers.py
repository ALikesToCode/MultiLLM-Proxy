from flask import jsonify, request
import logging
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APIError(Exception):
    def __init__(self, message, status_code=500, payload=None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

def init_error_handlers(app):
    @app.errorhandler(APIError)
    def handle_api_error(error):
        """Handle API errors without full traceback"""
        logger.error(f"API Error: {error.message}")
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        """Handle unexpected errors without full traceback"""
        error_msg = str(error)
        logger.error(f"Unexpected error: {error_msg}")
        return jsonify({
            "error": "An unexpected error occurred",
            "message": error_msg
        }), 500

    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 errors"""
        if request.path == '/favicon.ico':
            return app.send_static_file('favicon.ico')
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 errors without recursion"""
        error_msg = str(error)
        logger.error(f"Internal server error: {error_msg}")
        return jsonify({
            "error": "Internal server error",
            "message": error_msg
        }), 500