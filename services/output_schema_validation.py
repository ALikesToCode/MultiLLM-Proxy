"""Bounded, content-free validation of an explicit managed output contract."""

from __future__ import annotations

import copy
import logging
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from jsonschema import Draft4Validator, Draft6Validator, Draft7Validator, Draft201909Validator, Draft202012Validator
from jsonschema.validators import extend
from referencing import Registry
from referencing.exceptions import Unresolvable

from services.free_json_contract import (
    JsonOutputError, iter_schema_nodes, parse_json_output, schema_validator,
)

OPTION = "multillm_output_validation"
ENV_KEY = "OUTPUT_SCHEMA_VALIDATION_ENABLED"
MAX_BODY_BYTES = 1024 * 1024
MAX_ERROR_PATHS = 100
MAX_OUTPUT_DEPTH = 32
MAX_OUTPUT_NODES = 4096
MAX_VALIDATION_STEPS = 10000
MAX_VALIDATION_DEPTH = 64
MAX_VALIDATION_SECONDS = 0.1
MAX_NODE_PRODUCT = 100000
MAX_UNIQUE_ITEMS = 128
logger = logging.getLogger(__name__)
_warned_invalid_setting = False


class OutputValidationError(ValueError):
    """An error envelope that cannot contain schema or generated content."""

    def __init__(self, code, *, status=400, reason=None, paths=()):
        self.status = status
        self.code = code
        self.reason = reason
        self.paths = list(paths)[:MAX_ERROR_PATHS]
        super().__init__(code)

    def body(self):
        error = {"code": self.code, "message": "Explicit output validation failed"}
        if self.reason is not None:
            error.update(reason=self.reason, paths=self.paths)
        return {"error": error}


def violation(reason, paths=()):
    return OutputValidationError("output_schema_violation", status=502, reason=reason, paths=paths)


def enabled(config):
    global _warned_invalid_setting
    value = config.get(ENV_KEY, os.environ.get(ENV_KEY, ""))
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return False
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"", "false", "0", "no", "off"}:
            return False
    if not _warned_invalid_setting:
        logger.warning("Invalid OUTPUT_SCHEMA_VALIDATION_ENABLED setting; validation disabled")
        _warned_invalid_setting = True
    return False


def _node_count(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_OUTPUT_DEPTH or count > MAX_OUTPUT_NODES:
            raise ValueError("JSON complexity limit")
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        pending.extend((child, depth + 1) for child in children)
    return count


@dataclass(frozen=True)
class OutputContract:
    schema: Any
    validator_class: Any
    schema_nodes: int


def _pointer_target(schema, reference):
    if reference == "#":
        return schema
    if not reference.startswith("#/"):
        return None
    target = schema
    try:
        for part in unquote(reference[2:]).split("/"):
            key = part.replace("~1", "/").replace("~0", "~")
            target = target[int(key)] if isinstance(target, list) else target[key]
    except (KeyError, IndexError, ValueError, TypeError):
        return None
    return target


def _check_work_safety(schema):
    pending, visited, scheduled = [schema], set(), {id(schema)}
    while pending:
        for node in iter_schema_nodes(pending.pop()):
            if id(node) in visited:
                continue
            visited.add(id(node))
            # Regex evaluation cannot be interrupted by a keyword budget.
            if "pattern" in node or "patternProperties" in node:
                raise ValueError("Regex schemas exceed bounded validation support")
            if node is not schema and ("$schema" in node or "$id" in node or "id" in node):
                raise ValueError("Nested dialect or reference scope changes are unsupported")
            for name in ("$ref", "$dynamicRef", "$recursiveRef"):
                if name not in node:
                    continue
                reference = node[name]
                if not isinstance(reference, str) or not reference.startswith("#"):
                    raise ValueError("Only local references are supported")
                # JSON pointers may target schemas stored under literal keywords.
                target = _pointer_target(schema, reference)
                if isinstance(target, dict) and id(target) not in visited and id(target) not in scheduled:
                    scheduled.add(id(target))
                    pending.append(target)


def prepare_validation(payload, config):
    """Keep the disabled path untouched; prepare and strip only explicit opt-in."""
    if not enabled(config) or OPTION not in payload:
        return payload, None
    if payload.get("stream"):
        raise OutputValidationError("output_validation_requires_nonstream")
    option = payload[OPTION]
    if (not isinstance(option, dict) or set(option) != {"mode", "schema"}
            or option.get("mode") != "strict" or not isinstance(option["schema"], (dict, bool))):
        raise OutputValidationError("output_validation_invalid_option")
    schema = option["schema"]
    try:
        validator = schema_validator(schema)
        if type(validator) not in {Draft4Validator, Draft6Validator, Draft7Validator, Draft201909Validator, Draft202012Validator}:
            raise ValueError("Unsupported bounded validation dialect")
        _check_work_safety(schema)
        count = _node_count(schema)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise OutputValidationError("output_validation_invalid_schema") from None
    bounded_schema = copy.deepcopy(schema)
    if isinstance(bounded_schema, dict):
        # evolve() must retain the budgeted validator when following a root reference.
        bounded_schema.pop("$schema", None)
    return {key: value for key, value in payload.items() if key != OPTION}, OutputContract(
        bounded_schema, type(validator), count,
    )


def _bounded_validator(contract):
    steps, depth = 0, 0
    expires = time.monotonic() + MAX_VALIDATION_SECONDS

    def bounded(callback, keyword):
        def validate(validator, value, instance, schema):
            nonlocal steps, depth
            steps += 1
            depth += 1
            try:
                if (steps > MAX_VALIDATION_STEPS or depth > MAX_VALIDATION_DEPTH
                        or time.monotonic() >= expires):
                    raise violation("work_limit")
                if keyword == "uniqueItems" and value and isinstance(instance, list) and len(instance) > MAX_UNIQUE_ITEMS:
                    raise violation("work_limit")
                yield from callback(validator, value, instance, schema)
            finally:
                depth -= 1
        return validate

    cls = extend(contract.validator_class, {
        name: bounded(callback, name) for name, callback in contract.validator_class.VALIDATORS.items()
    })
    return cls(contract.schema, registry=Registry())


def _redacted_path(path):
    # Object keys can be generated content; only structural array indexes survive.
    return "".join("/" + (str(part) if isinstance(part, int) else "*") for part in path)


def validate_contents(contents, contract):
    """All choices share one keyword and elapsed-time budget."""
    validator = _bounded_validator(contract)
    nodes = 0
    for content in contents:
        nodes += _validate_content(content, contract, validator, nodes)


def _validate_content(content, contract, validator, prior_nodes):
    try:
        instance = parse_json_output(content)
    except JsonOutputError:
        raise violation("invalid_json") from None
    try:
        nodes = _node_count(instance)
        if (prior_nodes + nodes) * contract.schema_nodes > MAX_NODE_PRODUCT:
            raise violation("work_limit")
        paths = []
        for error in validator.iter_errors(instance):
            paths.append(_redacted_path(error.absolute_path))
            if len(paths) >= MAX_ERROR_PATHS:
                break
    except OutputValidationError:
        raise
    except (ValueError, RecursionError, OverflowError):
        raise violation("work_limit") from None
    except Unresolvable:
        raise violation("schema_mismatch") from None
    if paths:
        raise violation("schema_mismatch", paths)
    return nodes


def output_contents(envelope, protocol):
    """Select structured text without translating or modifying the provider body."""
    if not isinstance(envelope, dict):
        raise violation("invalid_response")
    if protocol == "chat":
        choices = envelope.get("choices")
        if not isinstance(choices, list) or not 1 <= len(choices) <= MAX_ERROR_PATHS:
            raise violation("invalid_response")
        result = [choice.get("message", {}).get("content") for choice in choices
                  if isinstance(choice, dict) and isinstance(choice.get("message"), dict)]
        if len(result) != len(choices):
            raise violation("invalid_response")
        return result
    blocks = envelope.get("content") if protocol == "messages" else None
    if protocol == "responses":
        output = envelope.get("output")
        if not isinstance(output, list):
            raise violation("invalid_response")
        blocks = []
        for item in output:
            if not isinstance(item, dict):
                raise violation("invalid_response")
            if item.get("type") == "message":
                if not isinstance(item.get("content"), list):
                    raise violation("invalid_response")
                blocks.extend(item["content"])
    if not isinstance(blocks, list):
        raise violation("invalid_response")
    text = [block.get("text") for block in blocks
            if isinstance(block, dict) and block.get("type") in {"text", "output_text"}]
    if not text or not all(isinstance(part, str) for part in text):
        raise violation("invalid_response")
    return ["".join(text)]
