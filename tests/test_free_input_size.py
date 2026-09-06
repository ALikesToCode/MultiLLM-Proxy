"""Oversized individual requests are distinct from exhausted account quotas."""

import json

from flask import Response

from services.free_compatibility import inspect_compatibility


def test_model_input_size_limit_allows_compatibility_fallback():
    body = json.dumps({"error": {
        "message": "Request too large for model `example` on input tokens per minute "
        "(ITPM): Limit 7000, Requested 7228, please reduce your message size.",
        "type": "tokens",
        "code": "rate_limit_exceeded",
    }})
    response, incompatible = inspect_compatibility(Response(body, status=413))
    assert incompatible is True
    assert response.get_data(as_text=True) == body


def test_account_rate_limit_is_not_request_compatibility():
    original = Response(json.dumps({"error": {
        "message": "Request too large for model `example`: daily quota exhausted",
    }}), status=429, headers={"Retry-After": "120"})
    response, incompatible = inspect_compatibility(original)
    assert incompatible is False
    assert response is original
    assert response.headers["Retry-After"] == "120"


def test_generic_payload_limit_is_not_model_compatibility():
    body = json.dumps({"error": {"message": "Request body exceeds server limit"}})
    response, incompatible = inspect_compatibility(Response(body, status=413))
    assert incompatible is False
    assert response.get_data(as_text=True) == body
