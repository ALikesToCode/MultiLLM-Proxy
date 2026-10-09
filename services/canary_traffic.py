"""Reviewed route cohorts; identity and content never enter storage or telemetry."""
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass
from threading import Lock

from flask import current_app, g, has_request_context, request

from error_handlers import APIError
from services import intelligence_d1_store

HEADER = "X-MultiLLM-Canary-Cohort"
logger = logging.getLogger(__name__)
_warned: set[str] = set()
_lock = Lock()
_counts: dict[tuple[str, str, str], int] = {}
_MAX_COUNT_KEYS = 800
_REVISION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SCHEMA = """CREATE TABLE IF NOT EXISTS canary_traffic (
    route_id TEXT PRIMARY KEY,
    route_updated_at TEXT NOT NULL,
    configuration TEXT NOT NULL
)"""


def warn_once(reason: str) -> None:
    with _lock:
        if reason in _warned:
            return
        _warned.add(reason)
    logger.warning("Canary traffic %s; using baseline routing", reason)


def enabled(environ=None) -> bool:
    source = os.environ if environ is None else environ
    flag = str(source.get("CANARY_TRAFFIC_ENABLED") or "").strip().lower()
    if flag not in {"", "0", "false", "no", "off", "1", "true", "yes", "on"}:
        warn_once("flag is invalid")
        return False
    return flag in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class CanaryConfig:
    enabled: bool = False
    mode: str = "shadow"
    baseline: int = 100
    candidate: int = 0
    salt_revision: str = "1"
    approved_candidates: tuple[str, ...] = ()

    @property
    def weights(self) -> dict[str, int]:
        return {"baseline": self.baseline, "candidate": self.candidate}

    def as_dict(self) -> dict:
        return {"enabled": self.enabled, "mode": self.mode, "weights": self.weights,
                "salt_revision": self.salt_revision, "approved_candidates": list(self.approved_candidates)}


def normalize_config(raw: object, candidates) -> CanaryConfig:
    fields = {"enabled", "mode", "weights", "salt_revision", "approved_candidates"}
    if not isinstance(raw, dict) or set(raw) - fields:
        raise ValueError("Canary configuration must be an object with supported fields")
    flag = raw.get("enabled", False)
    mode = raw.get("mode", "shadow")
    weights = raw.get("weights", {"baseline": 100, "candidate": 0})
    revision = raw.get("salt_revision", "1")
    approved = raw.get("approved_candidates", [])
    if type(flag) is not bool or not isinstance(mode, str) or mode not in {"shadow", "live"}:
        raise ValueError("Canary enabled must be a boolean and mode must be shadow or live")
    if (not isinstance(weights, dict) or set(weights) != {"baseline", "candidate"}
            or any(type(value) is not int or value < 0 for value in weights.values())
            or sum(weights.values()) != 100):
        raise ValueError("Canary weights must be non-negative integers summing to 100")
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise ValueError("Canary salt revision must be a bounded identifier")
    if (not isinstance(approved, list) or len(approved) > 16
            or any(not isinstance(model, str) or model not in candidates for model in approved)
            or len(set(approved)) != len(approved)):
        raise ValueError("Approved canary candidates must be distinct models in this route")
    if flag and weights["candidate"] and not approved:
        raise ValueError("Candidate traffic requires an approved candidate")
    return CanaryConfig(flag, mode, weights["baseline"], weights["candidate"], revision, tuple(approved))


def assign_cohort(policy: CanaryConfig, *, principal, session, route_id, key) -> str:
    if not policy.enabled:
        return "baseline"
    if not isinstance(key, (str, bytes)) or not key:
        warn_once("assignment secret is unavailable")
        return "baseline"
    if (not isinstance(principal, str) or not principal.strip()
            or not isinstance(session, str) or not session.strip()):
        return "baseline"
    # JSON framing distinguishes separators in session and principal values.
    try:
        message = json.dumps(["multillm-canary-v1", principal, session, route_id, policy.salt_revision],
                             ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        digest = hmac.new(key.encode("utf-8") if isinstance(key, str) else key, message, hashlib.sha256).digest()
    except UnicodeError:
        return "baseline"
    bucket = int.from_bytes(digest[:4], "big") % 100
    return "baseline" if bucket < policy.baseline else "candidate"


def session_identifier(payload: dict, user: dict) -> str | None:
    """Match prompt cache affinity's session sources, without its prefix fallback."""
    headers = {name.lower(): value for name, value in request.headers.items()}
    metadata = payload.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    values = (headers.get("x-opencode-session"), headers.get("session-id"), headers.get("thread-id"),
              payload.get("session_id"), payload.get("conversation_id"), metadata.get("session_id"),
              metadata.get("conversation_id"), user.get("session_id"))
    return next((value for value in values if isinstance(value, str) and value.strip()), None)


def authenticated_principal(user: dict) -> str | None:
    identity = user.get("id") or user.get("username")
    return json.dumps([user.get("tenant_id"), identity], ensure_ascii=False, separators=(",", ":")) if identity else None


@dataclass
class CanaryAssignment:
    route_id: str
    cohort: str
    mode: str
    proposed_order: tuple[str, ...]
    dispatch_order: tuple[str, ...]

    def observe(self, eligible_order) -> None:
        event = {"route_id": self.route_id, "cohort": self.cohort, "mode": self.mode,
                 "proposed_order": list(self.proposed_order), "eligible_order": list(eligible_order)}
        g.multillm_canary = event
        with _lock:
            key = (self.route_id, self.cohort, self.mode)
            if key in _counts or len(_counts) < _MAX_COUNT_KEYS:
                _counts[key] = _counts.get(key, 0) + 1

    def decorate(self, response):
        response.headers[HEADER] = f"{self.cohort}; mode={self.mode}"
        return response


def prepare_request(route, payload: dict) -> CanaryAssignment | None:
    if not enabled() or not route.canary.enabled or not has_request_context():
        return None
    user = getattr(g, "authenticated_user", None)
    user = user if isinstance(user, dict) else {}
    # Use the same authenticated tenant/user pair as prompt cache affinity.
    principal = authenticated_principal(user)
    cohort = assign_cohort(route.canary, principal=principal, session=session_identifier(payload, user),
                           route_id=route.id, key=current_app.config.get("JWT_SECRET"))
    approved = set(route.canary.approved_candidates)
    candidate_order = tuple(model for model in route.candidates if model in approved) + tuple(
        model for model in route.candidates if model not in approved)
    proposed = candidate_order if cohort == "candidate" else route.candidates
    dispatch = proposed if cohort == "candidate" and route.canary.mode == "live" else route.candidates
    return CanaryAssignment(route.id, cohort, route.canary.mode, proposed, dispatch)


def cohort_counts() -> list[dict]:
    with _lock:
        return [{"route_id": route, "cohort": cohort, "mode": mode, "count": count}
                for (route, cohort, mode), count in sorted(_counts.items())]


def decorate_current_response(response):
    event = getattr(g, "multillm_canary", None)
    if event is not None:
        response.headers[HEADER] = f"{event['cohort']}; mode={event['mode']}"
    return response


def local_configurations(connection) -> dict:
    if not enabled():
        return {}
    if connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='canary_traffic'").fetchone() is None:
        warn_once("configuration storage is unavailable")
        return {}
    return {row["route_id"]: (row["route_updated_at"], row["configuration"])
            for row in connection.execute("SELECT route_id, route_updated_at, configuration FROM canary_traffic")}


def stored_config(configurations, route_id, updated_at, candidates) -> CanaryConfig:
    row = configurations.get(route_id)
    if row is None or row[0] != updated_at:
        return CanaryConfig()
    try:
        raw = json.loads(row[1]) if isinstance(row[1], str) else row[1]
        return normalize_config(raw, candidates)
    except (ValueError, TypeError):
        warn_once("stored configuration is invalid")
        return CanaryConfig()


def save_local_configuration(connection, route_id, updated_at, policy: CanaryConfig) -> None:
    connection.execute(_SCHEMA)
    connection.execute("""INSERT INTO canary_traffic (route_id, route_updated_at, configuration)
        VALUES (?, ?, ?) ON CONFLICT(route_id) DO UPDATE SET
        route_updated_at=excluded.route_updated_at, configuration=excluded.configuration""",
        (route_id, updated_at, json.dumps(policy.as_dict(), separators=(",", ":"))))


def durable_request(operation, **values):
    try:
        result = intelligence_d1_store.request_private_intelligence(
            {"version": 1, "operation": operation, **values}, endpoint="auto_routes")
        if not isinstance(result, dict) or result.get("version") != 1 or "error" in result:
            raise ValueError("Unconfirmed canary storage operation")
        return result
    except intelligence_d1_store.PrivateIntelligenceError as error:
        if error.status in {400, 409}:
            raise APIError("Canary route save was rejected", error.status) from None
    except Exception:
        pass
    raise APIError("Canary route storage is unavailable; the route was not saved", 503) from None


def durable_configurations() -> dict:
    if not enabled():
        return {}
    try:
        response = durable_request("canary_list")
        rows = response.get("routes")
        if not isinstance(rows, list) or len(rows) > 200:
            raise ValueError("Invalid configuration list")
        return {row["route_id"]: (row["updated_at"], row["canary"]) for row in rows}
    except (APIError, KeyError, TypeError, ValueError, sqlite3.Error):
        warn_once("configuration storage is unavailable")
        return {}
