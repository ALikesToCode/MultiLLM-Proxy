"""Oversized individual requests are distinct from exhausted account quotas."""

import json

from flask import Response

from services.free_compatibility import inspect_compatibility, inspect_compatibility_detail
from services.free_model_policy import FreeCandidate
from services.free_route_diagnostics import failure_detail


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


def test_compatibility_categories_do_not_expose_error_content():
    candidate = FreeCandidate("groq:synthetic", "groq", "synthetic", True, "free-tier-attested")
    cases = [
        (413, "Request too large for model private-model", "input_too_large"),
        (400, "Too many images for private-model", "image_limit"),
        (422, "json_schema is not supported by private-model", "output_format"),
        (400, "vision input is not supported by private-model", "vision_input"),
    ]
    for status, message, expected in cases:
        _, category = inspect_compatibility_detail(Response(json.dumps({"error": {"message": message}}), status=status))
        assert category == expected
        detail = failure_detail(candidate, 502, status, "unsupported_parameters", compatibility=category)
        assert detail["compatibility"] == expected
        assert "private-model" not in json.dumps(detail)
    detail = failure_detail(candidate, 502, 413, "unsupported_parameters", compatibility="private-model")
    assert "compatibility" not in detail
