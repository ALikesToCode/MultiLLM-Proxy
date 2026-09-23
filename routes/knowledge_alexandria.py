"""Alexandria request contracts shared by REST, dashboard and MCP entry points."""

import json
import re

from services.knowledge_client import KnowledgeError

_ID = {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,80}$"}
_CREDITS = {"type": "integer", "minimum": 0, "maximum": 100000}
_CONTRACTS = {
    "search": ("Discover Alexandria capabilities for free. Only returned quote ids can be inspected or executed.",
               {"query": {"type": "string", "minLength": 1, "maxLength": 500},
                "limit": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5}}, ["query"]),
    "inspect": ("Inspect a discovered capability's inputs and response contract for free.",
                {"quote_id": _ID}, ["quote_id"]),
    "execute": (("Spend Firecrawl credits to execute a recently discovered quote. Choose options from its contract; "
                "reserve_credits counts against the allowance but is not an upstream price cap. Per-record pricing "
                "requires accept_variable_cost=true. Reuse request_id for the same request; never retry with a new id "
                 "after an unknown outcome. Report the returned cost to the user."),
                {"quote_id": _ID, "request_id": _ID, "options": {"type": "object"}, "reserve_credits": _CREDITS,
                 "accept_variable_cost": {"type": "boolean", "default": False}},
                ["quote_id", "request_id", "options", "reserve_credits"]),
    "receipt": ("Read a previous request's credit receipt without executing the provider again. No charge.",
                {"request_id": _ID}, ["request_id"]),
}
OPERATIONS = tuple("alexandria." + name for name in _CONTRACTS)
TOOLS = [{
    "name": "knowledge_alexandria_" + name, "description": description,
    "inputSchema": {"type": "object", "additionalProperties": False, "properties": properties, "required": required},
    "annotations": {"readOnlyHint": name != "execute", "openWorldHint": name != "receipt"},
} for name, (description, properties, required) in _CONTRACTS.items()]


def parse_request(operation, payload):
    """Reject malformed public inputs before forwarding to the private service."""
    _, properties, required = _CONTRACTS[operation.split(".", 1)[1]]
    if not isinstance(payload, dict) or set(payload) - properties.keys() or any(key not in payload for key in required):
        raise KnowledgeError("invalid_request", "Missing or unsupported Alexandria fields.", 400)
    for name, value in payload.items():
        kind = properties[name]["type"]
        valid = True
        if kind == "string":
            valid = isinstance(value, str) and bool(value.strip())
            if valid:
                valid = bool(re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value)) if name.endswith("_id") else (
                    len(value) <= 500 and not re.search(r"[\x00-\x1f\x7f]", value))
        elif kind == "integer":
            valid = type(value) is int and properties[name]["minimum"] <= value <= properties[name]["maximum"]
        elif kind == "boolean":
            valid = type(value) is bool
        elif kind == "object":
            valid = isinstance(value, dict) and len(json.dumps(value, ensure_ascii=False)) <= 16000
        if not valid:
            raise KnowledgeError("invalid_request", f"Invalid Alexandria {name}.", 400)
    return payload
