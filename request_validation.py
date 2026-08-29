import json
import re
from typing import Any, Dict, Optional

from flask import request

from error_handlers import APIError

GEMINI_MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def json_object_body() -> dict:
    """Return the request JSON object or raise a stable client error."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise APIError("Request body must be a JSON object", status_code=400)
    return payload


def validated_gemini_model_id(value: Any) -> str:
    """Return a bare Gemini model ID that cannot alter the request URL."""
    if not isinstance(value, str):
        raise APIError("Gemini model must be a string", status_code=400)

    model_id = value.strip()
    if model_id.startswith("models/"):
        model_id = model_id.removeprefix("models/")
    if not GEMINI_MODEL_ID_PATTERN.fullmatch(model_id):
        raise APIError("Invalid Gemini model identifier", status_code=400)
    return model_id


def decode_json_object_bytes(data: Optional[bytes]) -> Dict[str, Any]:
    """Decode an optional JSON object, treating non-object JSON as empty."""
    if not data:
        return {}

    parsed = json.loads(data)
    return parsed if isinstance(parsed, dict) else {}
