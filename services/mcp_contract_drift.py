"""Bounded, offline MCP schema digests and conservative compatibility reports."""

import hashlib
import json
import logging
import math
import os
import struct

from services.knowledge_client import KnowledgeError

CONTRACT_VERSION = "1.0.0"
FORMAT = "multillm-mcp-contract-v1"
MAX_CANONICAL_BYTES = 256 * 1024
MAX_DEPTH = 64
MAX_NODES = 65536
_warned = False


def digests_enabled(value=None):
    """Empty or malformed configuration cannot change existing traffic."""
    global _warned
    if value is None:
        value = os.environ.get("MCP_CONTRACT_DIGESTS_ENABLED", "")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("", "false", "0"):
            return False
        if normalized in ("true", "1"):
            return True
    if not _warned:
        logging.getLogger(__name__).warning("Invalid MCP_CONTRACT_DIGESTS_ENABLED; contract digests are disabled.")
        _warned = True
    return False


def canonical_value(value):
    """Typed JSON nodes with Unicode-scalar key ordering and binary64 numbers.

    Tagged nodes avoid collisions with schema strings. Numeric equality uses the
    exact finite binary64 representation in both runtimes, including integer/float
    equivalence and normalized negative zero. No schema keyword is discarded.
    """
    remaining = MAX_NODES

    def text(value):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("Contract strings must contain Unicode scalar values.")
        return value

    def node(item, depth):
        nonlocal remaining
        remaining -= 1
        if depth > MAX_DEPTH or remaining < 0:
            raise ValueError("Contract exceeds canonical depth or node limits.")
        if item is None:
            return ["null"]
        if isinstance(item, bool):
            return ["boolean", item]
        if isinstance(item, (int, float)):
            if abs(item) > 2**53 - 1 or not math.isfinite(item):
                raise ValueError("Contract numbers must be finite and within the interoperable range.")
            return ["number", struct.pack(">d", float(item) if item else 0.0).hex()]
        if isinstance(item, str):
            return ["string", text(item)]
        if isinstance(item, list):
            return ["array", [node(child, depth + 1) for child in item]]
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            return ["object", [[text(key), node(item[key], depth + 1)] for key in sorted(item)]]
        raise ValueError("Contract contains a non-JSON value.")

    encoded = json.dumps(node(value, 0), ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise ValueError("Contract exceeds canonical byte limit.")
    return encoded


def contract_payload(definition, contract_version=CONTRACT_VERSION):
    if not isinstance(definition, dict) or not isinstance(definition.get("name"), str) or "inputSchema" not in definition:
        raise ValueError("A tool contract requires a name and inputSchema.")
    return {"name": definition["name"], "inputSchema": definition["inputSchema"],
            "outputSchema": definition.get("outputSchema"), "contractVersion": contract_version}


def canonical_contract(definition, contract_version=CONTRACT_VERSION):
    return canonical_value(contract_payload(definition, contract_version))


def contract_digest(definition, contract_version=CONTRACT_VERSION):
    return hashlib.sha256(canonical_contract(definition, contract_version).encode("utf-8")).hexdigest()


def catalogue_digest(definitions, contract_version=CONTRACT_VERSION):
    contracts = [contract_payload(tool, contract_version) for tool in sorted(definitions, key=lambda tool: tool["name"])]
    return hashlib.sha256(canonical_value(contracts).encode("utf-8")).hexdigest()


def discovery_contract(entries, scopes, toolsets=None, *, enabled=False):
    """Filter before hashing so unauthorized tools cannot affect visible digests."""
    tools = [entry["definition"] for entry in entries
             if ("admin" in scopes or entry["scope"] in scopes)
             and (toolsets is None or entry["toolset"] in toolsets)]
    if not enabled:
        return {"tools": tools}
    return {"tools": [{**tool, "_meta": {**tool.get("_meta", {}), "contract_digest": contract_digest(tool)}} for tool in tools],
            "_meta": {"contract_digest": catalogue_digest(tools)}}


def check_contract_pin(definition, pin, *, enabled=False):
    """Call after authorization and before dispatch; no hash work without a pin."""
    if not enabled or pin is None:
        return
    if not isinstance(pin, str) or len(pin) != 64 or pin != contract_digest(definition):
        raise KnowledgeError("mcp_contract_mismatch", "The pinned MCP tool contract has changed. Refresh discovery.", 409)


def _type_set(value):
    if value is None:
        return {"null", "boolean", "object", "array", "number", "integer", "string"}
    types = {value} if isinstance(value, str) else set(value) if isinstance(value, list) else set()
    if "number" in types:
        types.add("integer")
    return types


def _schema_changes(old, new, path, changes, *, output=False):
    if canonical_value(old) == canonical_value(new):
        return
    if not isinstance(old, dict) or not isinstance(new, dict):
        grade = "breaking" if old is True and new is False else "review-required"
        changes.append({"path": path, "kind": "schema_changed", "classification": grade})
        return
    old_props, new_props = old.get("properties", {}), new.get("properties", {})
    if isinstance(old_props, dict) and isinstance(new_props, dict):
        for name in sorted(old_props.keys() - new_props.keys()):
            changes.append({"path": f"{path}/properties/{name}", "kind": "property_removed", "classification": "breaking"})
        for name in sorted(new_props.keys() - old_props.keys()):
            grade = "breaking" if name in new.get("required", []) else "review-required" if output else "compatible"
            changes.append({"path": f"{path}/properties/{name}", "kind": "property_added", "classification": grade})
        for name in sorted(old_props.keys() & new_props.keys()):
            _schema_changes(old_props[name], new_props[name], f"{path}/properties/{name}", changes, output=output)
    for key in sorted(old.keys() | new.keys()):
        if key == "properties" and isinstance(old_props, dict) and isinstance(new_props, dict):
            continue
        if canonical_value(old.get(key)) == canonical_value(new.get(key)) and (key in old) == (key in new):
            continue
        grade, kind = "review-required", "keyword_changed"
        if key == "required" and isinstance(old.get(key, []), list) and isinstance(new.get(key, []), list):
            added = set(new.get(key, [])) - set(old.get(key, []))
            removed = set(old.get(key, [])) - set(new.get(key, []))
            grade = "breaking" if added else "compatible" if removed else "review-required"
            kind = "required_changed"
        elif key == "type":
            before, after = _type_set(old.get(key)), _type_set(new.get(key))
            grade = "breaking" if before - after else "compatible" if after - before else "review-required"
            kind = "type_changed"
        if output and grade == "compatible":
            grade = "review-required"
        changes.append({"path": f"{path}/{key}", "kind": kind, "classification": grade})


def diff_contracts(old, new, *, old_version=CONTRACT_VERSION, new_version=CONTRACT_VERSION):
    """Unknown keyword/constraint changes require review; only proven additions pass."""
    before, after = _indexed(old), _indexed(new)
    changes = []
    for name in sorted(before.keys() - after.keys()):
        changes.append({"path": name, "kind": "tool_removed", "classification": "breaking"})
    for name in sorted(after.keys() - before.keys()):
        changes.append({"path": name, "kind": "tool_added", "classification": "compatible"})
    for name in sorted(before.keys() & after.keys()):
        _schema_changes(before[name]["inputSchema"], after[name]["inputSchema"], f"{name}/inputSchema", changes)
        if canonical_value(before[name].get("outputSchema")) != canonical_value(after[name].get("outputSchema")):
            if "outputSchema" in before[name] and "outputSchema" not in after[name]:
                changes.append({"path": f"{name}/outputSchema", "kind": "output_schema_removed", "classification": "breaking"})
            elif "outputSchema" not in before[name]:
                changes.append({"path": f"{name}/outputSchema", "kind": "output_schema_added", "classification": "review-required"})
            else:
                _schema_changes(before[name]["outputSchema"], after[name]["outputSchema"], f"{name}/outputSchema", changes, output=True)
    if old_version != new_version:
        changes.append({"path": "contractVersion", "kind": "version_changed", "classification": "review-required"})
    grades = {change["classification"] for change in changes}
    return {"classification": "breaking" if "breaking" in grades else "review-required" if "review-required" in grades else "compatible",
            "changes": changes}


def _indexed(definitions):
    result = {}
    for tool in definitions:
        contract_payload(tool)
        if tool["name"] in result:
            raise ValueError("Duplicate tool name in contract catalogue.")
        result[tool["name"]] = tool
    return result


VECTOR_DEFINITIONS = [
    {"name": "knowledge_test", "inputSchema": {"type": "object", "properties": {
        "b": {"type": ["string", "null"]}, "a": {"minimum": 1.0, "x-vendor": {"東京": "café", "values": [True, None, -0.0, 1e-7]}}},
        "required": ["b", "a"]}, "outputSchema": {"type": "string"}},
    {"name": "knowledge_😀", "inputSchema": {"\ue000": 1, "😀": 2, "type": "object", "anyOf": [{"type": "string"}, {"type": "number"}]}},
    {"name": "knowledge_test", "inputSchema": True},
]


def baseline_json(definitions):
    _indexed(definitions)
    baseline = {"format": FORMAT, "contract_version": CONTRACT_VERSION,
                "vectors": [{"definition": tool, "contract_version": CONTRACT_VERSION,
                             "canonical": canonical_contract(tool), "digest": contract_digest(tool)} for tool in VECTOR_DEFINITIONS],
                "tools": [{"definition": tool, "digest": contract_digest(tool)} for tool in definitions]}
    return json.dumps(baseline, indent=2, ensure_ascii=False) + "\n"
