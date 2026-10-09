"""Content-free alert configuration and aggregate observation through private state."""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import struct
from datetime import datetime, timezone
from urllib.parse import urlsplit

from services import control_state_d1

logger = logging.getLogger(__name__)
MAX_BYTES = 8192
MAX_RULES = 20
MAX_REVISION = 2**53 - 1
ID = re.compile(r"[0-9a-f]{64}\Z")
WINDOW = re.compile(r"(?:current|[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?)\Z")
KINDS = {"spend", "unknown_price", "provider_circuit", "pool_exhaustion", "provider_health"}
BASES = {"spend": "gateway_cost_estimate", "unknown_price": "unknown_price_coverage"}
_warned: set[str] = set()


class AlertError(Exception):
    def __init__(self, code="invalid_gateway_alert", status=400):
        self.code, self.status = code, status
        super().__init__(code)


def warn_once(name):
    if name not in _warned:
        _warned.add(name)
        logger.warning("Invalid gateway alert setting (%s)", name)


def number(value):
    return type(value) in (int, float) and 0 <= value <= 1e12 and math.isfinite(value)


def revision(value):
    return type(value) is int and 0 <= value < MAX_REVISION


def encoded(value, limit=MAX_BYTES):
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(text.encode()) > limit:
            raise AlertError("gateway_alert_too_large", 413)
        return text
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise AlertError() from None


def origin(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in value) or "\\" in value:
        raise AlertError()
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or "?" in value or "#" in value
                or parsed.port not in (None, 443) or not re.fullmatch(r"[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+", host)
                or host.rsplit(".", 1)[-1] in {"localhost", "local", "internal", "invalid", "test", "home", "lan"}
                or host.rsplit(".", 1)[-1].isdigit() or host.startswith("metadata.")):
            raise AlertError()
        return "https://" + host
    except ValueError:
        raise AlertError() from None


def settings():
    raw = os.environ.get("GATEWAY_ALERTS_ENABLED", "").strip().lower()
    enabled = raw in {"1", "true", "yes", "on"}
    if raw not in {"", "0", "1", "false", "true", "no", "yes", "off", "on"}:
        warn_once("GATEWAY_ALERTS_ENABLED")
    raw_list = os.environ.get("GATEWAY_ALERT_WEBHOOK_ALLOWLIST", "").strip() or "[]"
    try:
        values = json.loads(raw_list)
        if not isinstance(values, list) or len(values) > 20:
            raise AlertError()
        allowlist = {origin(value) for value in values}
        if any(value not in {origin(value), origin(value) + "/", origin(value) + ":443", origin(value) + ":443/"} for value in values):
            raise AlertError()
    except (ValueError, TypeError, RecursionError, AlertError):
        warn_once("GATEWAY_ALERT_WEBHOOK_ALLOWLIST")
        return False, set()
    return enabled, allowlist


def validate_destination(value, allowlist):
    if origin(value) not in allowlist:
        raise AlertError("gateway_alert_destination_not_allowed")
    return value


def numeric_identity(value):
    # Binary64 identity keeps integer/decimal rule hashes identical across both runtimes.
    return "n:" + struct.pack("!d", value).hex() if type(value) in (int, float) else value


def validate_rules(values, providers):
    if not isinstance(values, list) or len(values) > MAX_RULES:
        raise AlertError()
    result, seen = [], set()
    for value in values:
        if not isinstance(value, dict) or not isinstance(value.get("kind"), str) or value["kind"] not in KINDS:
            raise AlertError()
        kind = value["kind"]
        allowed = {"kind", "period", "budget_usd", "thresholds"} if kind == "spend" else (
            {"kind", "period", "threshold_percent"} if kind == "unknown_price" else {"kind", "provider", "failures"} if kind == "provider_health" else {"kind", "provider"})
        if set(value) - allowed:
            raise AlertError()
        rule = {"kind": kind}
        if kind in {"spend", "unknown_price"}:
            if not isinstance(value.get("period"), str) or value["period"] not in {"day", "month"}:
                raise AlertError()
            rule["period"] = value["period"]
        else:
            if not isinstance(value.get("provider"), str) or value["provider"] not in providers:
                raise AlertError()
            rule["provider"] = value["provider"]
        if kind == "spend":
            budget = value.get("budget_usd")
            thresholds = value.get("thresholds", [85, 100])
            if (not number(budget) or budget <= 0 or not isinstance(thresholds, list) or not 1 <= len(thresholds) <= 4
                    or any(not number(t) or not 0 < t <= 100 for t in thresholds) or len(set(thresholds)) != len(thresholds)):
                raise AlertError()
            rule.update(budget_usd=budget, thresholds=sorted(thresholds))
        elif kind == "unknown_price":
            threshold = value.get("threshold_percent", 0)
            if not number(threshold) or threshold > 100:
                raise AlertError()
            rule["threshold_percent"] = threshold
        elif kind == "provider_health":
            failures = value.get("failures", 3)
            if type(failures) is not int or not 1 <= failures <= 100:
                raise AlertError()
            rule["failures"] = failures
        canonical = {key: [numeric_identity(v) for v in value] if isinstance(value, list) else numeric_identity(value)
                     for key, value in rule.items()}
        identifier = hashlib.sha256(encoded(canonical).encode()).hexdigest()
        if identifier in seen:
            raise AlertError()
        seen.add(identifier)
        result.append({**rule, "id": identifier})
    encoded(result)
    return result


def valid_payload(value):
    if not isinstance(value, dict) or set(value) != {"event", "rule_id", "revision", "occurred_at", "basis", "value", "threshold", "window", "provider"}:
        return False
    return (value["event"] in KINDS and isinstance(value["rule_id"], str) and bool(ID.fullmatch(value["rule_id"]))
            and revision(value["revision"]) and number(value["occurred_at"]) and number(value["value"])
            and number(value["threshold"]) and value["basis"] == BASES.get(value["event"], "observed_health")
            and isinstance(value["window"], str) and bool(WINDOW.fullmatch(value["window"]))
            and (value["provider"] is None or value["provider"] in known_providers()))


def known_providers():
    from config import Config
    return set(Config.API_BASE_URLS)


def valid_status(value):
    if (not isinstance(value, dict) or set(value) != {"version", "revision", "rules", "webhook_configured", "events"}
            or type(value["version"]) is not int or value["version"] != 1 or not revision(value["revision"])
            or type(value["webhook_configured"]) is not bool or not isinstance(value["rules"], list)):
        return False
    try:
        rules = validate_rules([{k: v for k, v in row.items() if k != "id"} for row in value["rules"]], known_providers())
        if rules != value["rules"] or not isinstance(value["events"], list) or len(value["events"]) > 100:
            return False
        for row in value["events"]:
            if (not isinstance(row, dict) or set(row) != {"id", "state", "attempts", "last_attempt_at", "error_code", "payload"}
                    or not isinstance(row["id"], str) or not ID.fullmatch(row["id"])
                    or row["state"] not in {"pending", "delivered", "failed"} or type(row["attempts"]) is not int
                    or not 0 <= row["attempts"] <= 3 or row["error_code"] not in {None, "delivery_failed", "rule_replaced", "invalid_payload", "attempts_exhausted"}
                    or row["last_attempt_at"] is not None and not number(row["last_attempt_at"]) or not valid_payload(row["payload"])):
                return False
        encoded(value, limit=65536)
    except (AlertError, TypeError, AttributeError):
        return False
    return True


def call(operation, **values):
    if not settings()[0]:
        raise AlertError("not_found", 404)
    if not control_state_d1.using_d1():
        raise AlertError("gateway_alert_storage_unavailable", 503)
    try:
        result = control_state_d1.call("alerts", operation, **values)
    except Exception as error:
        if getattr(error, "status", None) == 409:
            raise AlertError("gateway_alert_revision_conflict", 409) from None
        raise AlertError("gateway_alert_storage_unavailable", 503) from None
    if operation in {"get", "configure"}:
        valid = valid_status(result)
    else:
        valid = (isinstance(result, dict) and set(result) == {"version", "queued"} and result["version"] == 1
                 and type(result["queued"]) is int and 0 <= result["queued"] <= 80)
    if not valid:
        raise AlertError("gateway_alert_storage_unavailable", 503)
    return result


def configure(body, providers):
    if not isinstance(body, dict) or set(body) != {"revision", "destination", "rules"} or not revision(body["revision"]):
        raise AlertError()
    encoded(body)
    destination = validate_destination(body["destination"], settings()[1])
    rules = validate_rules(body["rules"], providers)
    result = call("configure", revision=body["revision"], configuration={"destination": destination, "rules": rules})
    if result["revision"] != body["revision"] + 1 or result["rules"] != rules:
        raise AlertError("gateway_alert_storage_unavailable", 503)
    return result


def collect_observations(rules, *, usage=None, health=None, now=None):
    from services.usage_ledger import LEDGER
    from services.health_checks import passive_alert_health
    current = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() if now is None else now, timezone.utc)
    store, health_reader = usage if usage is not None else LEDGER.store(), health or passive_alert_health
    states = health_reader({r["provider"] for r in rules if "provider" in r})
    summaries, result = {}, []
    for rule in rules:
        kind, period = rule["kind"], rule.get("period")
        if period and period not in summaries:
            since = current.strftime("%Y-%m-%d" if period == "day" else "%Y-%m-01")
            rows = store.summary("day", since, current.strftime("%Y-%m-%d"), principal=None, limit=31)
            totals = {name: sum(row.get(name, 0) or 0 for row in rows) for name in ("cost_usd", "requests", "priced_requests")}
            if any(not number(v) for v in totals.values()) or totals["priced_requests"] > totals["requests"]:
                raise AlertError("gateway_alert_usage_unavailable", 503)
            summaries[period] = totals
        if kind == "spend":
            value = summaries[period]["cost_usd"]
        elif kind == "unknown_price":
            totals = summaries[period]
            value = 100 * (totals["requests"] - totals["priced_requests"]) / totals["requests"] if totals["requests"] else 0
        else:
            state = states.get(rule["provider"], {})
            field = {"provider_circuit": "circuit_open", "pool_exhaustion": "pool_exhausted", "provider_health": "consecutive_failures"}[kind]
            value = int(state.get(field, 0))
        result.append({"rule_id": rule["id"], "value": value, "basis": BASES.get(kind, "observed_health"),
                       "window": current.strftime("%Y-%m-%d" if period == "day" else "%Y-%m") if period else "current"})
    return result


def observe(*, collect=None):
    if not settings()[0]:
        return {"queued": 0}
    status = call("get")
    if not status["rules"]:
        return {"version": 1, "queued": 0}
    observations = (collect or collect_observations)(status["rules"])
    encoded(observations)
    return call("observe", revision=status["revision"], observations=observations)


def observe_safely():
    if settings()[0]:
        try:
            observe()
        except Exception:
            logger.warning("Gateway alert observation unavailable")
