"""Local JSON Schema subset; unsupported keywords never trigger retrieval or errors."""

import math

from services.tool_argument_parser import MAX_NODES, check_bounds, strict_loads

MAX_ERRORS = 32


def matches_type(kind, value):
    finite = type(value) is int or (type(value) is float and math.isfinite(value))
    return {
        "object": isinstance(value, dict), "array": isinstance(value, list),
        "string": isinstance(value, str), "boolean": type(value) is bool,
        "null": value is None, "number": finite,
        "integer": finite and int(value) == value,
    }.get(kind, True)


def types(schema):
    result = schema.get("type", [])
    result = [result] if isinstance(result, str) else result if isinstance(result, list) else []
    result = [kind for kind in result if isinstance(kind, str)]
    return [*result, "null"] if result and schema.get("nullable") is True else result


def json_equal(left, right):
    # Python equates True and 1; JSON Schema does not.
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(json_equal(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(json_equal(a, b) for a, b in zip(left, right))
    return left == right


def validate_arguments(schema, value):
    """Return bounded, value-free errors, using paths declared by the schema only."""
    try:
        check_bounds(schema)
        check_bounds(value)
    except (ValueError, TypeError, RecursionError, OverflowError, UnicodeError):
        return ["$: complexity limit exceeded"]
    return _validate(schema, value, "$", [MAX_NODES])[:MAX_ERRORS]


def _validate(schema, value, path, budget):
    budget[0] -= 1
    if budget[0] < 0:
        return [f"{path}: validation limit exceeded"]
    if schema is False:
        return [f"{path}: value is not allowed"]
    if not isinstance(schema, dict):
        return []
    errors = []
    allowed = types(schema)
    if allowed and not any(matches_type(kind, value) for kind in allowed):
        return [f"{path}: expected {' or '.join(str(t) for t in allowed)}"]
    if "enum" in schema and isinstance(schema["enum"], list):
        if not any(json_equal(value, item) for item in schema["enum"]):
            errors.append(f"{path}: not in enum")
    if "const" in schema and not json_equal(value, schema["const"]):
        errors.append(f"{path}: does not match const")
    for key in ("anyOf", "oneOf"):
        branches = schema.get(key)
        if isinstance(branches, list):
            successes = 0
            for branch in branches:
                if budget[0] <= 0:
                    return [f"{path}: validation limit exceeded"]
                successes += not _validate(branch, value, path, budget)
            if successes == 0 or (key == "oneOf" and successes != 1):
                errors.append(f"{path}: does not satisfy {key}")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        properties = properties if isinstance(properties, dict) else {}
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if isinstance(key, str) and key not in value:
                    errors.append(f"{path}.{key}: required property missing")
        if schema.get("additionalProperties") is False and value.keys() - properties.keys():
            errors.append(f"{path}: additional properties are not allowed")
        for key, child in properties.items():
            if key in value:
                errors.extend(_validate(child, value[key], f"{path}.{key}", budget))
                if len(errors) >= MAX_ERRORS:
                    break
    if isinstance(value, list):
        _bounds(errors, schema, len(value), path, "minItems", "maxItems")
        for index, item in enumerate(value):
            errors.extend(_validate(schema.get("items", {}), item, f"{path}[{index}]", budget))
            if len(errors) >= MAX_ERRORS:
                break
    if isinstance(value, str):
        _bounds(errors, schema, len(value), path, "minLength", "maxLength")
    if type(value) in (int, float):
        if type(value) is float and not math.isfinite(value):
            errors.append(f"{path}: expected finite number")
        _bounds(errors, schema, value, path, "minimum", "maximum")
    return errors[:MAX_ERRORS]


def _bounds(errors, schema, value, path, minimum, maximum):
    for key, failed in ((minimum, lambda bound: value < bound), (maximum, lambda bound: value > bound)):
        bound = schema.get(key)
        if type(bound) in (int, float) and failed(bound):
            errors.append(f"{path}: violates {key}")


def coerce(schema, value, budget=None):
    """Coerce existing values only; never synthesize a required property."""
    budget = [MAX_NODES] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0:
        return value
    if not isinstance(schema, dict) or not validate_arguments(schema, value):
        return value
    for union in ("anyOf", "oneOf"):
        branches = schema.get(union)
        if isinstance(branches, list):
            candidates = [coerce(branch, value, budget) for branch in branches]
            valid = [item for item in candidates if not validate_arguments(schema, item)]
            if valid and all(json_equal(valid[0], item) for item in valid):
                return valid[0]
            return value
    allowed = types(schema)
    candidates = []
    for kind in allowed:
        candidate = value
        if kind in ("integer", "number") and isinstance(value, str):
            try:
                number = strict_loads(value.strip())
                if matches_type(kind, number) and type(number) in (int, float):
                    candidate = int(number) if kind == "integer" else number
            except (ValueError, RecursionError):
                pass
        elif kind == "boolean" and isinstance(value, str) and value.lower() in ("true", "false"):
            candidate = value.lower() == "true"
        elif kind == "array" and not isinstance(value, list):
            candidate = [value]
        elif kind == "string" and type(value) in (int, float) and matches_type("number", value):
            candidate = str(value)
        candidate = _children(schema, candidate, budget)
        if not validate_arguments(schema, candidate):
            candidates.append(candidate)
    if not allowed:
        return _children(schema, value, budget)
    if candidates and all(json_equal(candidates[0], item) for item in candidates):
        return candidates[0]
    return value


def _children(schema, value, budget):
    if isinstance(value, dict) and isinstance(schema.get("properties", {}), dict):
        return {k: coerce(schema.get("properties", {}).get(k, {}), v, budget) for k, v in value.items()}
    if isinstance(value, list):
        return [coerce(schema.get("items", {}), v, budget) for v in value]
    return value
