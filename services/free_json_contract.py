"""Validate free-route output contracts without retrieving external schemas."""

import json
import math

from jsonschema import Draft202012Validator, SchemaError, ValidationError
from jsonschema.validators import validator_for
from referencing import Registry
from referencing.exceptions import Unresolvable

MAX_SCHEMA_BYTES = 64 * 1024
MAX_SCHEMA_DEPTH = 32
MAX_SCHEMA_NODES = 4096
_SCHEMA_MAPS = {
    "properties",
    "patternProperties",
    "$defs",
    "definitions",
    "dependentSchemas",
}
_SCHEMA_LISTS = {"allOf", "anyOf", "oneOf", "prefixItems"}
_SCHEMA_VALUES = {
    "additionalProperties",
    "additionalItems",
    "unevaluatedProperties",
    "unevaluatedItems",
    "contains",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
    "contentSchema",
    "items",
}


class JsonOutputError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _check_bounds(value):
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_SCHEMA_DEPTH or count > MAX_SCHEMA_NODES:
            raise ValueError("Schema exceeds complexity limits")
        children = (
            item.values()
            if isinstance(item, dict)
            else item
            if isinstance(item, list)
            else ()
        )
        pending.extend((child, depth + 1) for child in children)


def _check_references(schema):
    pending = [schema]
    while pending:
        item = pending.pop()
        if not isinstance(item, dict):
            continue
        for name in ("$ref", "$dynamicRef", "$recursiveRef"):
            if name in item and (
                not isinstance(item[name], str) or not item[name].startswith("#")
            ):
                raise ValueError("Only local schema references are supported")
        for key, value in item.items():
            if key in _SCHEMA_MAPS and isinstance(value, dict):
                pending.extend(value.values())
            elif key in _SCHEMA_LISTS and isinstance(value, list):
                pending.extend(value)
            elif key in _SCHEMA_VALUES:
                pending.extend(value if isinstance(value, list) else [value])
            elif key == "dependencies" and isinstance(value, dict):
                pending.extend(v for v in value.values() if isinstance(v, dict))


def _schema_validator(response_format):
    wrapper = response_format.get("json_schema")
    if (
        not isinstance(wrapper, dict)
        or not isinstance(wrapper.get("name"), str)
        or not wrapper["name"].strip()
    ):
        raise ValueError("json_schema requires a name and schema")
    schema = wrapper.get("schema")
    if not isinstance(schema, (dict, bool)):
        raise ValueError("json_schema.schema must be an object or boolean")
    if "strict" in wrapper and not isinstance(wrapper["strict"], bool):
        raise ValueError("json_schema.strict must be a boolean")
    _check_bounds(schema)
    if len(json.dumps(schema, allow_nan=False).encode()) > MAX_SCHEMA_BYTES:
        raise ValueError("Schema exceeds size limit")
    _check_references(schema)
    cls = (
        validator_for(schema, default=None)
        if isinstance(schema, dict) and "$schema" in schema
        else Draft202012Validator
    )
    if cls is None:
        raise ValueError("Unsupported JSON Schema dialect")
    cls.check_schema(schema)
    # An explicit empty registry disables jsonschema's legacy remote retrieval.
    return cls(schema, registry=Registry())


def validate_response_format(response_format):
    if response_format is None:
        return
    if not isinstance(response_format, dict) or response_format.get("type") not in (
        "text",
        "json_object",
        "json_schema",
    ):
        raise ValueError("Unsupported response_format")
    if response_format["type"] == "json_schema":
        try:
            _schema_validator(response_format)
        except (SchemaError, RecursionError) as error:
            raise ValueError("Invalid JSON Schema") from error


def json_output_requested(response_format) -> bool:
    return isinstance(response_format, dict) and response_format.get("type") in (
        "json_object",
        "json_schema",
    )


def _invalid_constant(value):
    raise ValueError("Non-finite JSON number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number")
    return number


def check_json_output(content, response_format):
    if not isinstance(content, str):
        raise JsonOutputError("invalid_json")
    try:
        parsed = json.loads(
            content,
            parse_constant=_invalid_constant,
            parse_float=_finite_float,
            object_pairs_hook=_unique_object,
        )
    except (ValueError, RecursionError) as error:
        raise JsonOutputError("invalid_json") from error
    if response_format["type"] == "json_object" and not isinstance(parsed, dict):
        raise JsonOutputError("schema_mismatch")
    if response_format["type"] == "json_schema":
        try:
            _schema_validator(response_format).validate(parsed)
        except (ValidationError, SchemaError, Unresolvable, RecursionError) as error:
            raise JsonOutputError("schema_mismatch") from error


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON property")
        result[key] = value
    return result
