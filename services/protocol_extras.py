"""Bounded, source-scoped extras kept outside serialized protocol bodies."""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Collection, Mapping
from threading import Lock
from typing import Any

from services.protocol_translation.common import (
    CHAT,
    MESSAGES,
    PROTOCOLS,
    RESPONSES,
    ProtocolExtras,
    ProtocolIR,
    TranslationError,
    UpstreamFailure,
)

MAX_FIELDS = 32
MAX_BYTES = 16 * 1024
_PARAM = "_multillm.protocol_extras"
_REQUEST_FIELDS = {
    CHAT: frozenset({"seed", "logprobs", "top_logprobs"}),
    MESSAGES: frozenset({"top_k"}),
    RESPONSES: frozenset({"truncation"}),
}
_RESPONSE_FIELDS = {
    CHAT: frozenset({"system_fingerprint"}),
    MESSAGES: frozenset({"stop_sequence"}),
    RESPONSES: frozenset({"service_tier"}),
}
logger = logging.getLogger(__name__)
_warned = False
_warning_lock = Lock()


def enabled() -> bool:
    global _warned
    flag = os.environ.get("PROTOCOL_EXTRAS_ENABLED", "").strip().lower()
    if flag in {"", "0", "false", "no", "off"}:
        return False
    if flag in {"1", "true", "yes", "on"}:
        return True
    with _warning_lock:
        if not _warned:
            _warned = True
            logger.warning("Invalid PROTOCOL_EXTRAS_ENABLED; protocol extras disabled")
    return False


def _invalid(message: str) -> TranslationError:
    return TranslationError(message, param=_PARAM)


def _bounded(value: Any) -> None:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as error:
        raise _invalid("Protocol extras must contain bounded JSON values") from error
    if len(encoded) > MAX_BYTES:
        raise _invalid("Protocol extras exceed the 16 KiB limit")


def _valid_value(key: str, value: Any, kind: str) -> bool:
    if kind == "response":
        if key == "stop_sequence":
            return value is None or (isinstance(value, str) and len(value) <= 1024)
        if key == "system_fingerprint":
            return value is None or (isinstance(value, str) and
                re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value) is not None)
        return isinstance(value, str) and value in {"auto", "default", "flex", "priority", "scale"}
    if key == "logprobs":
        return type(value) is bool
    if key == "truncation":
        # Automatic truncation changes required input semantics across protocols.
        return value == "disabled"
    bounds = {"seed": (-(2**63), 2**63 - 1), "top_k": (0, 2**31 - 1), "top_logprobs": (0, 20)}
    low, high = bounds[key]
    return type(value) is int and low <= value <= high


def _fields(source: str, fields: Any, kind: str) -> tuple[tuple[str, Any], ...]:
    if not isinstance(fields, Mapping) or len(fields) > MAX_FIELDS:
        raise _invalid("Protocol extras must be an object with at most 32 fields")
    _bounded(fields)
    allowed = (_REQUEST_FIELDS if kind == "request" else _RESPONSE_FIELDS)[source]
    if any(key not in allowed for key in fields):
        raise _invalid("Protocol extras contain an unreviewed or unsupported field")
    if any(not _valid_value(key, value, kind) for key, value in fields.items()):
        raise _invalid("Protocol extras contain an unsupported field value")
    return tuple(sorted(fields.items()))


def capture_request_extras(payload: Mapping[str, Any], source: str) -> ProtocolExtras | None:
    """Validate client namespace only for managed traffic with the flag enabled."""
    if not enabled() or "_multillm" not in payload:
        return None
    namespace = payload["_multillm"]
    if not isinstance(namespace, Mapping):
        raise _invalid("The managed namespace must be an object")
    if any(key != "protocol_extras" for key in namespace):
        raise _invalid("The managed namespace contains an unknown option")
    if not namespace:
        return None
    _bounded(namespace)
    extra = namespace["protocol_extras"]
    if not isinstance(extra, Mapping) or set(extra) != {"source_protocol", "fields"}:
        raise _invalid("Protocol extras require source_protocol and fields only")
    recorded = extra["source_protocol"]
    if not isinstance(recorded, str) or recorded not in PROTOCOLS or recorded != source:
        raise _invalid("Protocol extras source must match the originating protocol")
    fields = _fields(recorded, extra["fields"], "request")
    if any(key in payload and payload[key] != value for key, value in fields):
        raise _invalid("Protocol extras conflict with an explicit request field")
    return ProtocolExtras(recorded, fields)


def validate_request_extras(payload: Mapping[str, Any], source: str) -> None:
    """Small strict-translator call site; never add the namespace to its output."""
    capture_request_extras(payload, source)


def _without_extras(payload: Mapping[str, Any], extras: ProtocolExtras | None) -> dict:
    excluded = {key for key, _ in extras.fields} if extras else set()
    excluded.add("_multillm")
    return {key: value for key, value in payload.items() if key not in excluded}


def request_to_ir(payload: Mapping[str, Any], source: str) -> ProtocolIR:
    """Create an explicit carrier independent of the client or provider body."""
    from services.protocol_translation import translate_request

    extras = capture_request_extras(payload, source)
    clean = _without_extras(payload, extras) if enabled() else dict(payload)
    return ProtocolIR(translate_request(clean, source, CHAT), extras)


def _emitted(extras: ProtocolExtras | None, target: str, admitted_fields: Collection[str],
             required_fields: Collection[str], kind: str) -> dict:
    if target not in PROTOCOLS:
        raise ValueError("Unknown target protocol")
    if extras is None:
        if required_fields:
            raise _invalid("Required protocol extras are unavailable")
        return {}
    if extras.source_protocol not in PROTOCOLS or extras.kind != kind or kind not in {"request", "response"}:
        raise _invalid("Protocol extras carrier has an invalid source or body kind")
    fields = dict(extras.fields)
    _fields(extras.source_protocol, fields, kind)
    emitted = {key: value for key, value in fields.items()
               if target == extras.source_protocol and key in admitted_fields}
    if any(key not in emitted for key in required_fields):
        raise _invalid("The target provider cannot represent required protocol extras")
    return emitted


def request_from_ir(ir: ProtocolIR, target: str, *, admitted_fields: Collection[str] = (),
                    required_fields: Collection[str] = ()) -> dict:
    """Emit only fields explicitly admitted by the selected provider contract."""
    from services.protocol_translation import translate_request

    fields = _emitted(ir.extras, target, admitted_fields, required_fields, "request") if enabled() else {}
    body = translate_request(ir.body, CHAT, target)
    return {**body, **fields}


def translate_managed_request(payload: Mapping[str, Any], source: str, target: str, *,
                              admitted_fields: Collection[str] = (),
                              required_fields: Collection[str] = ()) -> dict:
    """Named dispatch hook; raw callers continue to use the existing transport."""
    from services.protocol_translation import translate_request

    if not enabled():
        return translate_request(payload, source, target)
    if source == target:
        extras = capture_request_extras(payload, source)
        fields = _emitted(extras, target, admitted_fields, required_fields, "request")
        return {**_without_extras(payload, extras), **fields}
    ir = request_to_ir(payload, source)
    return request_from_ir(ir, target, admitted_fields=admitted_fields, required_fields=required_fields)


def validate_response_extras(payload: Mapping[str, Any]) -> None:
    """Upstream bodies cannot manufacture a trusted source namespace."""
    if enabled() and "_multillm" in payload:
        raise UpstreamFailure("The upstream response contains an internal protocol namespace")


def capture_response_extras(payload: Mapping[str, Any], source: str) -> ProtocolExtras | None:
    """Retain reviewed native response members, never an upstream carrier."""
    if source not in PROTOCOLS:
        raise ValueError("Unknown source protocol")
    validate_response_extras(payload)
    if enabled():
        fields = {key: payload[key] for key in _RESPONSE_FIELDS[source] if key in payload}
        try:
            return ProtocolExtras(source, _fields(source, fields, "response"), "response") if fields else None
        except TranslationError as error:
            raise UpstreamFailure("The upstream protocol extras have an invalid shape") from error
    return None


def response_to_ir(payload: Mapping[str, Any], source: str) -> ProtocolIR:
    from services.protocol_translation import translate_response

    extras = capture_response_extras(payload, source)
    clean = _without_extras(payload, extras) if enabled() else payload
    return ProtocolIR(translate_response(clean, source, CHAT), extras)


def response_from_ir(ir: ProtocolIR, target: str, *, admitted_fields: Collection[str] = (),
                     model: str | None = None, request: Mapping[str, Any] | None = None) -> dict:
    from services.protocol_translation import translate_response

    try:
        fields = _emitted(ir.extras, target, admitted_fields, (), "response") if enabled() else {}
    except TranslationError as error:
        raise UpstreamFailure("The upstream protocol extras have an invalid shape") from error
    return {**translate_response(ir.body, CHAT, target, model=model, request=request), **fields}


def translate_managed_response(payload: Mapping[str, Any], source: str, target: str, *,
                               model: str | None = None,
                               request: Mapping[str, Any] | None = None) -> dict:
    from services.protocol_translation import translate_response

    if not enabled():
        return translate_response(payload, source, target, model=model, request=request)
    ir = response_to_ir(payload, source)
    return response_from_ir(ir, target, model=model, request=request)


def extras_report(extras: ProtocolExtras | None, target: str, *,
                  admitted_fields: Collection[str] = ()) -> dict:
    """Fixed field paths describe IR retention separately from egress loss."""
    if extras is None:
        return {"fidelity": "exact", "fields": []}
    emitted = _emitted(extras, target, admitted_fields, (), extras.kind)
    fields = [{"path": f"{extras.kind}.protocol_extras.{key}",
               "classification": "exact" if key in emitted else "lossy",
               "reason": "Approved field re-emitted." if key in emitted else
                         "Approved field retained in IR and omitted from the target body.",
               "retained_in_ir": True, "re_emitted": key in emitted}
              for key, _ in extras.fields]
    return {"fidelity": "lossy" if any(f["classification"] == "lossy" for f in fields) else "exact",
            "fields": fields}


def managed_request_report(payload: Mapping[str, Any], source: str, target: str, *,
                           admitted_fields: Collection[str] = ()) -> dict:
    """Augment conversion diagnostics using the same validation as dispatch."""
    from services.conversion_diagnostics import combine_reports, request_report

    if not enabled():
        return request_report(payload, source, target)
    try:
        extras = capture_request_extras(payload, source)
        base = request_report(_without_extras(payload, extras), source, target)
        return combine_reports(base, extras_report(extras, target, admitted_fields=admitted_fields))
    except TranslationError:
        return {"fidelity": "unsupported", "fields": [{"path": "request.protocol_extras",
                "classification": "unsupported", "reason": "Protocol extras cannot be represented."}]}
