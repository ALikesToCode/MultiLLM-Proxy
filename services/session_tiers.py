"""Approved session lanes; retain hashes and policy markers, never content."""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

from services.intelligence_contract import GatewayError, identifier

logger = logging.getLogger(__name__)
_warned = set()
_warning_lock = threading.Lock()
MAX_ENTRIES = 10000
MAX_TOOLS = 128
LANES = {"main", "delegation", "aux"}


@dataclass(frozen=True)
class SessionTierSettings:
    enabled: bool = False
    ttl_seconds: int = 1800


def settings(environ=None):
    source = os.environ if environ is None else environ
    mode = (source.get("SESSION_TIER_MODE") or "off").strip() or "off"
    ttl = (source.get("SESSION_TIER_TTL_SECONDS") or "1800").strip() or "1800"
    try:
        if not ttl.isascii() or not ttl.isdigit():
            raise ValueError
        seconds = int(ttl)
        if mode not in {"off", "sticky"} or not 1 <= seconds <= 86400:
            raise ValueError
    except (TypeError, ValueError):
        with _warning_lock:
            if "settings" not in _warned:
                _warned.add("settings")
                logger.warning("Invalid session tier settings; session tiers disabled")
        return SessionTierSettings()
    return SessionTierSettings(mode == "sticky", seconds)


def _error(code, message, status=503):
    return GatewayError(code, message, status)


def _hash(*parts):
    return hashlib.sha256(json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _text(value, name, maximum=256):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise _error("invalid_session_tier", f"Invalid {name}", 400)
    return value


def validate_selection(lane, model, tier):
    if not isinstance(lane, str) or lane not in LANES or type(tier) is not int or not 0 <= tier <= 100:
        raise _error("invalid_session_tier", "Invalid lane or approved tier", 400)
    try:
        identifier(model)
    except (TypeError, ValueError):
        raise _error("invalid_session_tier", "Invalid approved model", 400) from None


def _tool_hash(call_id):
    return _hash("tool", _text(call_id, "tool call identifier", 200))


def _pending_after_messages(pending, messages):
    if not isinstance(messages, list) or len(messages) > 256:
        raise _error("invalid_session_tier", "Invalid session messages", 400)
    outstanding = set(pending)
    for message in messages:
        if not isinstance(message, dict):
            raise _error("invalid_session_tier", "Invalid session message", 400)
        if message.get("role") == "assistant":
            calls = message.get("tool_calls") or []
            if not isinstance(calls, list) or len(calls) > MAX_TOOLS:
                raise _error("session_tier_tool_limit", "Invalid tool call markers", 400)
            for call in calls:
                if not isinstance(call, dict):
                    raise _error("invalid_session_tier", "Invalid tool call marker", 400)
                outstanding.add(_tool_hash(call.get("id")))
        elif message.get("role") == "tool":
            outstanding.discard(_tool_hash(message.get("tool_call_id")))
        if len(outstanding) > MAX_TOOLS:
            raise _error("session_tier_tool_limit", "Too many outstanding tool calls", 400)
    return sorted(outstanding)


class LocalSessionTierStore:
    """Bounded process-local adapter; inject durable storage when needed."""
    def __init__(self, max_entries=MAX_ENTRIES):
        self.rows = {}
        self.max_entries = min(MAX_ENTRIES, max(1, max_entries))
        self.lock = threading.RLock()

    def transaction(self, scope, now, update):
        with self.lock:
            self.rows = {k: v for k, v in self.rows.items() if v["expires_at"] > now}
            row, result = update(copy.deepcopy(self.rows.get(scope)))
            if row is None:
                self.rows.pop(scope, None)
            else:
                if scope not in self.rows and len(self.rows) >= self.max_entries:
                    raise _error("session_tier_capacity", "Session tier capacity unavailable")
                self.rows[scope] = copy.deepcopy(row)
            return result


class SQLiteSessionTierStore:
    """Injected connection adapter; never migrates tables on traffic."""
    def __init__(self, connection):
        self.connection = connection
        self.lock = threading.RLock()

    def transaction(self, scope, now, update):
        with self.lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute("DELETE FROM session_tiers WHERE expires_at <= ?", (now,))
                cursor = self.connection.execute("SELECT * FROM session_tiers WHERE scope_hash = ?", (scope,))
                saved = cursor.fetchone()
                row = dict(zip([col[0] for col in cursor.description], saved)) if saved else None
                if row:
                    row["pending_tools"] = json.loads(row["pending_tools"])
                    row["safe_turn"] = bool(row["safe_turn"])
                row, result = update(row)
                if row is None:
                    self.connection.execute("DELETE FROM session_tiers WHERE scope_hash = ?", (scope,))
                else:
                    count = self.connection.execute("SELECT COUNT(*) FROM session_tiers").fetchone()[0]
                    if not saved and count >= MAX_ENTRIES:
                        raise _error("session_tier_capacity", "Session tier capacity unavailable")
                    self._save(scope, row)
                self.connection.commit()
                return result
            except sqlite3.Error:
                self.connection.rollback()
                raise _error("session_tier_storage_unavailable", "Session tier storage unavailable; apply its migration") from None
            except Exception:
                self.connection.rollback()
                raise

    def _save(self, scope, row):
        columns = ("lane", "tier", "approved_model", "actual_model", "policy_revision", "expires_at", "safe_turn", "pending_tools", "lease")
        values = [json.dumps(row[k]) if k == "pending_tools" else row[k] for k in columns]
        self.connection.execute(
            """INSERT INTO session_tiers (scope_hash, lane, tier, approved_model, actual_model,
                policy_revision, expires_at, safe_turn, pending_tools, lease)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope_hash) DO UPDATE SET lane=excluded.lane, tier=excluded.tier,
                approved_model=excluded.approved_model, actual_model=excluded.actual_model,
                policy_revision=excluded.policy_revision, expires_at=excluded.expires_at,
                safe_turn=excluded.safe_turn, pending_tools=excluded.pending_tools, lease=excluded.lease""",
            (scope, *values),
        )


class SessionTierTurn:
    def __init__(self, service, scope, row, candidates):
        self.service, self.scope, self.row = service, scope, row
        self.models = {c["model"] for c in candidates}

    def select(self, candidates):
        allowed = [c for c in candidates if c["model"] in self.models]
        return sorted(allowed, key=lambda c: c["model"] != self.row["actual_model"])

    def finish(self, candidate, *, success, tool_calls=(), credential_failed=False):
        def update(current):
            if not current or current["lease"] != self.row["lease"]:
                return current, None
            if credential_failed:
                return None, None
            if candidate is not None:
                if candidate["model"] not in self.models:
                    raise _error("session_tier_ineligible", "Actual route is outside approved tier")
                current["actual_model"] = candidate["model"]
            pending = set(current["pending_tools"])
            if not isinstance(tool_calls, (list, tuple)) or len(tool_calls) > MAX_TOOLS:
                raise _error("session_tier_tool_limit", "Too many outstanding tool calls")
            if any(not isinstance(call, dict) for call in tool_calls):
                raise _error("invalid_session_tier", "Invalid tool call marker")
            pending.update(_tool_hash(call.get("id")) for call in tool_calls)
            if len(pending) > MAX_TOOLS:
                raise _error("session_tier_tool_limit", "Too many outstanding tool calls")
            current.update(pending_tools=sorted(pending), safe_turn=bool(candidate and success), lease="")
            return current, None
        self.service.store.transaction(self.scope, self.service.clock(), update)


class SessionTiers:
    def __init__(self, store, *, clock=time.time, ttl_seconds=1800):
        self.store, self.clock, self.ttl_seconds = store, clock, ttl_seconds

    def begin(self, *, principal, session, lane, approved_model, approved_tier,
              revision, messages, candidates, unavailable=lambda c: False):
        validate_selection(lane, approved_model, approved_tier)
        scope = _hash("session-tier", _text(principal, "principal"), _text(session, "session"), lane)
        revision = _hash("revision", _text(revision, "policy revision", 512))
        now = self.clock()
        def update(row):
            if row and row["lease"]:
                raise _error("session_tier_busy", "A session lane already has an unresolved request", 409)
            if row and row["policy_revision"] != revision:
                row = None
            pending = _pending_after_messages(row["pending_tools"] if row else [], messages)
            safe = not pending and bool(messages) and messages[-1].get("role") == "user"
            change = row is None or (safe and row["safe_turn"] and (
                row["approved_model"] != approved_model or row["tier"] != approved_tier
            ))
            model = approved_model if change else row["approved_model"]
            tier = approved_tier if change else row["tier"]
            native_model = model.partition(":")[2]
            allowed = [c for c in candidates if c.get("quality_tier", 0) == tier
                       and c["model"].partition(":")[2] == native_model and not unavailable(c)]
            if change and not any(c["model"] == model for c in allowed):
                raise _error("session_tier_ineligible", "Approved model is not eligible")
            if not allowed:
                return None, _error("session_tier_ineligible", "No eligible route remains in approved tier")
            actual = model if change else row["actual_model"]
            row = {"lane": lane, "tier": tier, "approved_model": model, "actual_model": actual,
                   "policy_revision": revision, "expires_at": now + self.ttl_seconds,
                   "safe_turn": False, "pending_tools": pending, "lease": secrets.token_hex(16)}
            return row, SessionTierTurn(self, scope, row, allowed)
        result = self.store.transaction(scope, now, update)
        if isinstance(result, GatewayError):
            raise result
        return result


local_store = LocalSessionTierStore()


def prepare_session_tier(payload, *, principal, revision, candidates, store=None, environ=None, unavailable=lambda c: False):
    """Strip managed metadata before parsing; explicit routes never acquire a lane."""
    configured = settings(environ)
    if not configured.enabled or "session_tier" not in payload:
        return payload, None
    cleaned = {k: v for k, v in payload.items() if k != "session_tier"}
    if payload.get("model") != "auto:intelligence":
        return cleaned, None
    raw = payload["session_tier"]
    fields = {"session", "lane", "approved_model", "approved_tier"}
    if not isinstance(raw, dict) or set(raw) != fields:
        raise _error("invalid_session_tier", "Session tier requires session, lane and explicit approval", 400)
    service = SessionTiers(store if store is not None else local_store, ttl_seconds=configured.ttl_seconds)
    ticket = service.begin(principal=principal, revision=revision, candidates=candidates,
                           session=raw["session"], lane=raw["lane"], approved_model=raw["approved_model"],
                           approved_tier=raw["approved_tier"], messages=payload.get("messages", []), unavailable=unavailable)
    return cleaned, ticket
