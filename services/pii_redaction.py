"""Deterministic, opt-in PII transformation with request-local ownership."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from dataclasses import dataclass

from services.secret_scan import scan_payload, scan_text

MAX_INPUT_BYTES = 1024 * 1024
MAX_VALUES = 512
PREFIX = "__MLPII_"
TOKEN = re.compile(r"__MLPII_[0-9a-f]{64}__")
_EMAIL = re.compile(r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,4}(?![A-Za-z0-9.-])", re.ASCII)
_NUMBER = re.compile(r"(?<![A-Za-z0-9+])\+?[0-9](?:[0-9 ()-]{0,30}[0-9])?(?![0-9]|[ ()-]{1,4}[0-9])", re.ASCII)
_warned: set[str] = set()
logger = logging.getLogger(__name__)


class PIIRedactionError(ValueError):
    """A required transform could not be completed before dispatch."""


@dataclass(frozen=True)
class PIIPolicy:
    detectors: tuple[str, ...]
    mode: str


@dataclass(frozen=True)
class PreparedPayload:
    payload: object
    context: PIIContext | None = None
    skipped: bool = False


def _warn_once(name):
    if name not in _warned:
        _warned.add(name)
        logger.warning("Invalid PII configuration for %s; redaction disabled", name)


def resolve_policy(env, *, route="", key_scope=""):
    flag = str(env.get("PII_REDACTION_ENABLED", "")).strip().lower()
    if flag in {"", "false", "0", "no", "off"}:
        return None
    if flag not in {"true", "1", "yes", "on"}:
        _warn_once("PII_REDACTION_ENABLED")
        return None
    try:
        raw = str(env.get("PII_REDACTION_POLICY_JSON", "")).strip() or "{}"
        if len(raw.encode()) > 65536:
            raise ValueError
        policy = json.loads(raw)
        if not isinstance(policy, dict) or set(policy) - {"routes", "keys", "detectors", "mode"}:
            raise ValueError
        for name in ("routes", "keys", "detectors"):
            items = policy.get(name, [])
            if not isinstance(items, list) or len(items) > 512 or any(
                not isinstance(item, str) or not 1 <= len(item) <= 256 for item in items
            ):
                raise ValueError
        if set(policy.get("detectors", [])) - {"email", "phone", "card"}:
            raise ValueError
        mode = policy.get("mode", "required")
        if mode not in {"required", "best_effort"}:
            raise ValueError
        if route not in policy.get("routes", []) and (not key_scope or key_scope not in policy.get("keys", [])):
            return None
        detectors = tuple(policy.get("detectors", []))
        return PIIPolicy(detectors, mode) if detectors else None
    except (ValueError, TypeError, RecursionError):
        _warn_once("PII_REDACTION_POLICY_JSON")
        return None


def _luhn(digits):
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char) * (2 if index % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0 and len(set(digits)) > 1


def _findings(text, detectors):
    protected = [(item["start"], item["end"]) for item in scan_text(text)]
    found = []
    if "email" in detectors:
        found.extend((match.start(), match.end()) for match in _EMAIL.finditer(text))
    if "phone" in detectors or "card" in detectors:
        for match in _NUMBER.finditer(text):
            value = match.group()
            digits = "".join(char for char in value if char.isascii() and char.isdigit())
            card = 13 <= len(digits) <= 19 and _luhn(digits)
            phone = 10 <= len(digits) <= 15 and (value.startswith("+") or any(char in value for char in " ()-"))
            if "card" in detectors and card or "phone" in detectors and phone and len(digits) <= 15:
                found.append((match.start(), match.end()))
    end = -1
    for start, stop in sorted(found, key=lambda span: (span[0], -span[1])):
        if start < end or any(start < right and stop > left for left, right in protected):
            continue
        yield start, stop
        end = stop


class PIIContext:
    """Only this object owns the ephemeral secret and reversible values."""

    def __init__(self):
        self.secret = secrets.token_bytes(32)
        self.values: dict[str, str] = {}
        self.closed = False

    def issue(self, value):
        if self.closed:
            raise PIIRedactionError("PII request context is closed")
        token = PREFIX + hmac.new(self.secret, value.encode(), hashlib.sha256).hexdigest() + "__"
        if token in self.values and self.values[token] != value:
            raise PIIRedactionError("PII placeholder collision")
        if token not in self.values and len(self.values) >= MAX_VALUES:
            raise PIIRedactionError("PII request exceeds the value limit")
        self.values[token] = value
        return token

    def restore(self, text):
        return TOKEN.sub(lambda match: self.values.get(match.group(), match.group()), text)

    def close(self):
        self.values.clear()
        self.secret = b""
        self.closed = True


def map_strings(value, transform, *, depth=0, counter=None, field="", skip_secret_fields=False):
    counter = [0] if counter is None else counter
    counter[0] += 1
    if depth > 32 or counter[0] > 32768:
        raise PIIRedactionError("PII document exceeds the structure limit")
    if isinstance(value, str):
        if skip_secret_fields and scan_payload({field: value})["types"].get("secret_field"):
            return value
        return transform(value)
    if isinstance(value, list):
        return [map_strings(item, transform, depth=depth + 1, counter=counter, field=field,
                            skip_secret_fields=skip_secret_fields) for item in value]
    if isinstance(value, dict):
        return {key: map_strings(item, transform, depth=depth + 1, counter=counter, field=key,
                                skip_secret_fields=skip_secret_fields) for key, item in value.items()}
    return value


def prepare_payload(payload, env=None, *, route="", key_scope="", raw=False, firewall=None):
    env = os.environ if env is None else env
    policy = None if raw else resolve_policy(env, route=route, key_scope=key_scope)
    if policy is None:
        return PreparedPayload(payload)
    # A firewall refusal must not be caught by the best-effort PII policy.
    checked = firewall(payload) if firewall is not None else payload
    context = None
    try:
        if len(json.dumps(checked, ensure_ascii=False, allow_nan=False).encode()) > MAX_INPUT_BYTES:
            raise PIIRedactionError("PII request exceeds the input limit")
        context = PIIContext()

        def redact(text):
            parts, end = [], 0
            for start, stop in _findings(text, policy.detectors):
                parts.extend((text[end:start], context.issue(text[start:stop])))
                end = stop
            return "".join(parts) + text[end:]

        updated = map_strings(checked, redact, skip_secret_fields=True)
        if not context.values:
            context.close()
            return PreparedPayload(checked)
        return PreparedPayload(updated, context)
    except Exception:
        if context is not None:
            context.close()
        if policy.mode == "best_effort":
            return PreparedPayload(checked, skipped=True)
        raise PIIRedactionError("Required PII transformation failed before provider dispatch") from None


def current_context():
    from flask import g, has_request_context
    return getattr(g, "pii_context", None) if has_request_context() else None


def pii_request_hook():
    """After authentication/secret policy, before request identity and caches."""
    from flask import g, jsonify, request
    from services.retention_policy import RetentionPolicy
    from services.secret_firewall import protect_payload

    if request.method != "POST" or request.path not in {
        "/v1/chat/completions", "/v1/responses", "/v1/messages", "/intelligence/v1/chat/completions"
    }:
        return None
    user = getattr(g, "authenticated_user", None) or {}
    if not user or current_context() is not None:
        return None
    key_scope = str(user.get("id") or user.get("username") or "")
    if resolve_policy(os.environ, route=request.path, key_scope=key_scope) is None:
        return None
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None
    try:
        result = prepare_payload(payload, route=request.path, key_scope=key_scope, firewall=protect_payload)
    except PIIRedactionError:
        return jsonify({"error": {"code": "pii_redaction_failed", "message": "Required PII transformation failed before provider dispatch"}}), 422
    g.pii_redaction_skipped = result.skipped
    if result.context is None:
        return None
    if request.headers.get("Idempotency-Key") is not None:
        result.context.close()
        return jsonify({"error": {"code": "pii_idempotency_unsupported", "message": "Redacted requests cannot use idempotency replay"}}), 400
    g.pii_context = result.context
    g.pii_no_persistence = True
    # Existing exact/shared caches already bypass requests under zero retention.
    g.multillm_content_retention = RetentionPolicy("zero", True, "pii-request")
    request._cached_json = (result.payload, result.payload)
    return None


def register_pii_redaction(app):
    app.extensions.setdefault("gateway_after_authentication", []).append(pii_request_hook)

    @app.after_request
    def finish_pii(response):
        from services.pii_stream import rehydrate_response
        context = current_context()
        if context is not None and not context.closed:
            return rehydrate_response(response, context)
        return response

    @app.teardown_request
    def abandon_pii(error):
        from flask import g
        context = current_context()
        if context is not None and not getattr(g, "pii_stream_owned", False):
            context.close()
