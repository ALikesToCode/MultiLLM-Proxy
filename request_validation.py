from flask import request

from error_handlers import APIError


def json_object_body() -> dict:
    """Return the request JSON object or raise a stable client error."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise APIError("Request body must be a JSON object", status_code=400)
    return payload
