from flask import jsonify, request
import logging

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
        logger.error(f"API Error: {error.message}")
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        logger.error(f"Unexpected error: {str(error)}")
        return jsonify({
            "error": "An unexpected error occurred",
            "message": str(error)
        }), 500

    @app.errorhandler(404)
    def not_found_error(error):
        if request.path == '/favicon.ico':
            return app.send_static_file('favicon.ico')
        return jsonify({"error": "Not found"}), 404