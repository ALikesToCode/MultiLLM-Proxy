"""Outbound body policy, aggregate audit metadata and response counts."""

import hashlib
import json
import logging
import os
import re
from urllib.parse import parse_qsl, urlencode

from flask import g, has_request_context, request

from error_handlers import APIError
from services.secret_scan import redact_payload, scan_text

logger = logging.getLogger(__name__)
MODES = frozenset({"off", "observe", "redact", "block"})
HEADER = "X-MultiLLM-Secret-Scan"


class ScannedBody(bytes):
    """Body checked on the caller thread; retries reuse the checked bytes."""


def scan_mode(user=None, *, knowledge=False):
    if user is None and has_request_context():
        user = getattr(g, "authenticated_user", {})
    override = (user or {}).get("secret_scan_mode")
    mode = override if override in MODES else os.environ.get("SECRET_SCAN_DEFAULT", "redact").strip().lower()
    if mode not in MODES:
        mode = "redact"
    return "block" if knowledge and mode != "off" else mode


def _route():
    if not has_request_context():
        return "background"
    return str(request.url_rule) if request.url_rule else "unmatched"


def protect_payload(value, *, provider=None, user=None, knowledge=False):
    mode = scan_mode(user, knowledge=knowledge)
    if mode == "off":
        return value
    try:
        updated, report = redact_payload(value, mode=mode)
    except Exception as error:
        logger.warning("Secret scan unavailable type=%s", type(error).__name__)
        return value
    high, heuristic = report["high"], report["heuristic"]
    if not high and not heuristic:
        return value
    action = "blocked" if mode == "block" and high else "redacted" if mode == "redact" and high else "observed"
    if user is None and has_request_context():
        user = getattr(g, "authenticated_user", {})
    identity = (user or {}).get("id") or (user or {}).get("username")
    safe_identity = identity if isinstance(identity, str) and re.fullmatch(r"[A-Za-z0-9_:@.-]{1,128}", identity) else None
    if safe_identity and scan_text(safe_identity):
        safe_identity = "redacted_identity"
    safe_provider = provider if provider and re.fullmatch(r"[a-z0-9_-]{1,40}", provider) else None
    detail = json.dumps({"mode": mode, "action": action, "provider": safe_provider,
                         "types": report["types"]}, separators=(",", ":"))
    try:
        from services import audit_log
        audit_log.record("secret_scan", "refused" if action == "blocked" else "succeeded",
                         actor=safe_identity, target=_route(), detail=detail)
    except Exception as error:
        logger.warning("Secret scan audit unavailable type=%s", type(error).__name__)
    if has_request_context():
        counts = getattr(g, "secret_scan_counts", [0, 0])
        counts[0] += high if action == "redacted" else 0
        counts[1] += heuristic + (high if action == "observed" else 0)
        g.secret_scan_counts = counts
    if action == "blocked":
        raise APIError("High-confidence secrets detected in outbound content", 422,
                       {"error": "secret_detected", "types": report["types"], "high": high, "heuristic": heuristic})
    return updated


def protect_body(data, headers=None, *, provider=None, user=None):
    """Preserve unchanged bytes; check JSON and multipart text fields, not files."""
    if scan_mode(user) == "off" or not data or isinstance(data, ScannedBody):
        return data
    if not isinstance(data, (bytes, bytearray, str)):
        return data
    original = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    cache = getattr(g, "secret_scan_cache", {}) if has_request_context() else {}
    digest = hashlib.sha256(original).digest()
    if digest in cache:
        return cache[digest]
    content_type = next((str(v) for k, v in (headers or {}).items() if k.lower() == "content-type"), "")
    try:
        if content_type.lower().startswith("multipart/form-data"):
            value, rebuild = _multipart(original, content_type)
        elif content_type.lower().startswith("application/x-www-form-urlencoded"):
            pairs = parse_qsl(original.decode("utf-8"), keep_blank_values=True, max_num_fields=256)
            value = [{key: text} for key, text in pairs]
            rebuild = lambda updated: urlencode([(key, text) for part in updated for key, text in part.items()]).encode("utf-8")
        else:
            try:
                value = json.loads(original)
                rebuild = lambda updated: json.dumps(updated, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            except (ValueError, UnicodeError):
                value = original.decode("utf-8")
                rebuild = lambda updated: updated.encode("utf-8")
        updated = protect_payload(value, provider=provider, user=user)
        result = ScannedBody(rebuild(updated) if updated is not value else original)
    except APIError:
        raise
    except Exception as error:
        logger.warning("Secret scan body unavailable type=%s", type(error).__name__)
        return data
    if has_request_context() and len(cache) < 32 and sum(map(len, cache.values())) + len(result) <= 8_388_608:
        cache[digest] = result
        g.secret_scan_cache = cache
    return result


def _multipart(body, content_type):
    match = re.search(r'boundary=(?:"([^"\r\n]{1,200})"|([^;\s]{1,200}))', content_type)
    if not match:
        raise ValueError("Missing multipart boundary")
    marker = b"--" + (match[1] or match[2]).encode("ascii")
    parts = body.split(marker, 257)
    fields = {}
    for index, part in enumerate(parts[:256]):
        head, separator, text = part.partition(b"\r\n\r\n")
        if not separator or b"filename=" in head.lower() or len(head) > 8192:
            continue
        name = re.search(rb'name="([^"\r\n]{1,128})"', head)
        if name:
            fields[str(index)] = {name[1].decode("utf-8"): text.removesuffix(b"\r\n").decode("utf-8")}

    def rebuild(updated):
        for key, values in updated.items():
            index = int(key)
            if values != fields[key]:
                head = parts[index].partition(b"\r\n\r\n")[0]
                parts[index] = head + b"\r\n\r\n" + next(iter(values.values())).encode("utf-8") + b"\r\n"
        return marker.join(parts)
    return fields, rebuild


def init_secret_firewall(app):
    @app.after_request
    def secret_scan_header(response):
        counts = getattr(g, "secret_scan_counts", None)
        if counts and response.status_code < 400:
            response.headers[HEADER] = f"redacted={counts[0]}; observed={counts[1]}"
        return response
