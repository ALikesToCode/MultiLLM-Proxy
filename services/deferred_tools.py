"""Permission-first, local tool discovery with complete schemas and short-lived cursors."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from typing import Any

from flask import current_app, has_app_context
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from services import config_revision_sync, control_state_d1, mcp_contract_drift as drift
from services.knowledge_client import KnowledgeError

MAX_BYTES = 64 * 1024
RPC_ENVELOPE_RESERVE = 4096
MAX_LIMIT = 16
CURSOR_TTL = 120
MAX_GRANTS = 4096
_PROCESS_REVISION = secrets.token_hex(16)
_warned = False
_default = None


def enabled(value=None):
    global _warned
    value = os.environ.get("DEFERRED_TOOLS_ENABLED", "") if value is None else value
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        flag = value.strip().lower()
        if flag in {"", "0", "false", "off", "no"}:
            return False
        if flag in {"1", "true", "on", "yes"}:
            return True
    if not _warned:
        logging.getLogger(__name__).warning("Invalid DEFERRED_TOOLS_ENABLED; deferred tools disabled")
        _warned = True
    return False


def unavailable():
    return KnowledgeError("tool_grants_unavailable", "The tool grant authority is unavailable. No tool was executed.", 503)


def grant_revision():
    """Use the confirmed security revision, never an old or unconfirmed copy."""
    if not config_revision_sync.load_settings().enabled:
        return _PROCESS_REVISION
    sync = current_app.extensions.get("config_revision_sync") if has_app_context() else None
    if sync is None or not sync.settings.enabled:
        raise unavailable()
    state = sync.status()["domains"].get("model_grants")
    if not state or state["stale"] or type(state["revision"]) is not int:
        raise unavailable()
    return state["revision"]


class D1GrantReader:
    """Fixed private read through the existing model-state endpoint."""

    def __call__(self, principal):
        if not control_state_d1.using_d1():
            raise unavailable()
        result = control_state_d1.call("model_overrides", "tool_grants", principal=principal)
        if not isinstance(result, dict) or set(result) != {"version", "grants"} or type(result["version"]) is not int or result["version"] != 1:
            raise unavailable()
        return result["grants"]


def runtime_service():
    global _default
    if has_app_context() and "deferred_tools" in current_app.extensions:
        return current_app.extensions["deferred_tools"]
    if _default is None:
        _default = DeferredTools(D1GrantReader())
    return _default


def principal_for(user):
    identity = user.get("id") or user.get("username")
    scopes = user.get("scopes") or []
    if (not isinstance(identity, str) or not 0 < len(identity) <= 128 or identity == "*"
            or not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes)):
        raise KnowledgeError("invalid_principal", "The authenticated identity is unavailable.", 403)
    return {"id": identity, "scopes": ["admin"] if user.get("is_admin") else scopes}


def parse_discovery(params):
    if not isinstance(params, dict) or set(params) - {"query", "cursor", "limit"}:
        raise KnowledgeError("invalid_request", "Discovery accepts query, cursor and limit only.", 400)
    query, limit, cursor = params.get("query"), params.get("limit", MAX_LIMIT), params.get("cursor")
    if (not isinstance(query, str) or not query.strip() or len(query) > 500
            or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in query)
            or type(limit) is not int or not 1 <= limit <= MAX_LIMIT
            or cursor is not None and (not isinstance(cursor, str) or not 0 < len(cursor) <= 4096)):
        raise KnowledgeError("invalid_request", "Use a query up to 500 characters, limit 1–16 and a valid cursor.", 400)
    return query.strip().lower(), limit, cursor


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _hash(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _words(text):
    return set(re.findall(r"[^\W_]+", text.lower(), flags=re.UNICODE))


def rank_tools(definitions, query):
    tokens = _words(query)
    scored = []
    for tool in definitions:
        score = sum(weight * len(tokens & _words(tool.get(field, "")))
                    for field, weight in (("name", 3), ("title", 2), ("description", 1)))
        if score:
            scored.append((score, tool))
    return [tool for _, tool in sorted(scored, key=lambda item: (-item[0], item[1]["name"]))]


def _validated_grants(rows, identity):
    if not isinstance(rows, list) or len(rows) > MAX_GRANTS:
        raise unavailable()
    grants = {}
    for row in rows:
        if (not isinstance(row, dict) or row.get("principal_id") not in {"*", identity}
                or not isinstance(row.get("tool_name"), str) or not 0 < len(row["tool_name"]) <= 128
                or type(row.get("allowed")) is not int or row["allowed"] not in (0, 1)
                or type(row.get("revision")) is not int or not 0 <= row["revision"] <= 9007199254740991
                or not isinstance(row.get("scopes"), list) or not row["scopes"]
                or any(not isinstance(scope, str) or not 0 < len(scope) <= 80 for scope in row["scopes"])):
            raise unavailable()
        key = (row["principal_id"], row["tool_name"])
        if key in grants:
            raise unavailable()
        grants[key] = row
    return grants


def _permitted(entry, principal, grants):
    scopes = principal["scopes"]
    if "admin" not in scopes and entry["scope"] not in scopes:
        return False
    name = entry["definition"]["name"]
    row = grants.get((principal["id"], name), grants.get(("*", name)))
    return bool(row and row["allowed"] and ("admin" in scopes or all(scope in scopes for scope in row["scopes"])))


class DeferredTools:
    """Read grants for every operation; discovery never creates or caches permissions."""

    def __init__(self, read_grants, *, revision=grant_revision, clock=time.time, secret=None):
        self.read_grants, self.revision, self.clock = read_grants, revision, clock
        self._secret = secret if secret is not None else secrets.token_bytes(32)

    def _snapshot(self, principal):
        try:
            rows = self.read_grants(principal["id"])
            grants = _validated_grants(rows, principal["id"])
            revision = self.revision()
            if not isinstance(revision, (str, int)) or isinstance(revision, bool):
                raise unavailable()
            stamp = _hash([grants[key] for key in sorted(grants)])
            return grants, revision, stamp
        except KnowledgeError:
            raise
        except Exception:
            raise unavailable() from None

    def list_tools(self, entries, user):
        principal = principal_for(user)
        grants, _, _ = self._snapshot(principal)
        return [entry["definition"] for entry in entries if _permitted(entry, principal, grants)]

    def require_grant(self, entry, user):
        principal = principal_for(user)
        grants, _, _ = self._snapshot(principal)
        if not _permitted(entry, principal, grants):
            raise KnowledgeError("tool_not_granted", "The key is not granted permission for this tool.", 403)

    def authorize_call(self, entry, user, arguments):
        self.require_grant(entry, user)
        try:
            schema = entry["definition"]["inputSchema"]
            Draft202012Validator.check_schema(schema)
            valid = isinstance(arguments, dict) and Draft202012Validator(schema).is_valid(arguments)
        except (SchemaError, RecursionError, ValueError):
            raise KnowledgeError("tool_validation_unavailable", "The runtime tool schema is unavailable.", 503) from None
        if not valid:
            raise KnowledgeError("invalid_arguments", "The arguments do not match the complete runtime tool schema.", 400)
        self.require_grant(entry, user)

    def _sign(self, payload):
        raw = _json(payload).encode()
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        signature = hmac.new(self._secret, encoded.encode(), hashlib.sha256).hexdigest()
        return encoded + "." + signature

    def _decode(self, cursor, binding, count):
        try:
            encoded, signature = cursor.split(".")
            expected = hmac.new(self._secret, encoded.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError()
            raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            payload = json.loads(raw)
            if (not isinstance(payload, dict) or set(payload) != set(binding) | {"o", "exp"}
                    or any(payload.get(key) != value for key, value in binding.items())
                    or type(payload["o"]) is not int or not 0 < payload["o"] < count
                    or type(payload["exp"]) not in (int, float) or not self.clock() < payload["exp"] <= self.clock() + CURSOR_TTL):
                raise ValueError()
            return payload["o"], payload["exp"]
        except (ValueError, TypeError, KeyError, binascii.Error, UnicodeDecodeError):
            raise KnowledgeError("invalid_cursor", "The discovery cursor expired or its permissions or contract changed.", 400) from None

    def discover(self, entries, user, params, *, digests=False):
        query, limit, cursor = parse_discovery(params)
        principal = principal_for(user)
        grants, revision, stamp = self._snapshot(principal)
        tools = [entry["definition"] for entry in entries if _permitted(entry, principal, grants)]
        try:
            digest = drift.catalogue_digest(tools)
        except ValueError:
            raise KnowledgeError("tool_schema_too_large", "The authorized tool catalogue exceeds contract digest limits.", 413) from None
        if digests:
            tools = [{**tool, "_meta": {**tool.get("_meta", {}), "contract_digest": drift.contract_digest(tool)}} for tool in tools]
        ranked = rank_tools(tools, query)
        binding = {"v": 1, "p": _hash(principal), "d": digest, "r": revision, "g": stamp, "q": _hash(query), "l": limit}
        offset, expires = self._decode(cursor, binding, len(ranked)) if cursor else (0, self.clock() + CURSOR_TTL)
        page: dict[str, Any] = {"tools": [], "_meta": {"contract_digest": digest}}
        stop = min(len(ranked), offset + limit)
        for end in range(offset + 1, stop + 1):
            candidate = {"tools": ranked[offset:end], "_meta": page["_meta"]}
            if end < len(ranked):
                candidate["nextCursor"] = self._sign({**binding, "o": end, "exp": expires})
            # Reserve the envelope, including a maximally escaped 200-character request ID.
            if len(json.dumps(candidate, ensure_ascii=True).encode()) + RPC_ENVELOPE_RESERVE > MAX_BYTES:
                if not page["tools"]:
                    raise KnowledgeError("tool_schema_too_large", "A complete tool schema cannot fit in a discovery response.", 413)
                break
            page = candidate
        _, latest_revision, latest_stamp = self._snapshot(principal)
        if (revision, stamp) != (latest_revision, latest_stamp):
            raise KnowledgeError("tool_grants_changed", "Tool grants changed during discovery. Start discovery again.", 409)
        return page
