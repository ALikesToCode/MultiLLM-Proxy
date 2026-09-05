"""JSON syntax checks; schema conformance remains an upstream contract."""

import json


def json_output_requested(response_format) -> bool:
    return isinstance(response_format, dict) and response_format.get("type") in (
        "json_object",
        "json_schema",
    )


def _invalid_constant(value):
    raise ValueError("Non-finite JSON number")


def check_json_output(content, response_format):
    if not isinstance(content, str):
        raise ValueError("JSON output must be text")
    parsed = json.loads(content, parse_constant=_invalid_constant)
    if response_format["type"] == "json_object" and not isinstance(parsed, dict):
        raise ValueError("Expected a JSON object")
