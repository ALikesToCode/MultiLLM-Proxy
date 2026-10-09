"""Server-owned tenant bindings and atomic, content-free hierarchy administration."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from functools import lru_cache

from flask import current_app, g, has_request_context, jsonify

from services.enterprise_contract import AuthorityOperation, TenantContext, legacy_tenant
from services.sqlite_store import connect, storage_path

logger = logging.getLogger(__name__)
PRIVATE_URL = "http://intelligence.internal/v1/managed-state/tenants"
MAX_BODY_BYTES = 8192
_SLOTS = threading.BoundedSemaphore(8)
_ID = re.compile(r"[A-Za-z0-9_:.\-]{1,128}\Z")
OPERATIONS = frozenset({"org_list", "org_get", "org_create", "org_update", "team_list", "team_create",
                        "team_update", "member_list", "member_set", "workspaces", "binding_set", "resolve"})
ERROR_STATUSES = {"workspace_not_found": 404, "workspace_forbidden": 403, "principal_not_found": 404,
                  "revision_required": 428, "revision_conflict": 412, "tenant_limit_reached": 409,
                  "invalid_request": 400, "invalid_revision": 400, "tenant_storage_unavailable": 503}


class TenantError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


def error_response(error):
    return jsonify({"error": {"code": error.code, "message": "The workspace operation could not be authorized or stored."}}), error.status, {"Cache-Control": "no-store"}


@lru_cache(maxsize=1)
def _warn_once():
    logger.warning("Invalid ORGANISATIONS_ENABLED; organisations disabled")


def enabled():
    flag = os.environ.get("ORGANISATIONS_ENABLED", "").strip().lower()
    if flag in {"", "0", "false", "no", "off"}:
        return False
    if flag in {"1", "true", "yes", "on"}:
        return True
    _warn_once()
    return False


def _text(value, maximum=128):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise TenantError("invalid_request")
    return value


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise TenantError("invalid_request")
    return value


def _revision(value):
    if value is None:
        raise TenantError("revision_required", 428)
    if type(value) is not int or not 0 <= value < 9007199254740000:
        raise TenantError("invalid_revision")
    return value


def _legacy(principal):
    try:
        context = TenantContext(principal)
    except ValueError:
        context = TenantContext("principal:" + hashlib.sha256(principal.encode()).hexdigest())
    return legacy_tenant(AuthorityOperation(context, "workspace", 0, "resolve"))


def private_call(document):
    """Reuse the bounded private transport, with one submission and no replay."""
    from services import intelligence_d1_store as transport
    try:
        body = json.dumps(document, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError):
        raise TenantError("invalid_request") from None
    if len(body) > MAX_BODY_BYTES or not _SLOTS.acquire(blocking=False):
        raise TenantError("tenant_storage_unavailable", 503)
    stopped, results = threading.Event(), queue.Queue(maxsize=1)
    deadline = time.monotonic() + 5
    thread = threading.Thread(target=transport._submit,
        args=(PRIVATE_URL, body, stopped, deadline, results, _SLOTS, (200,), (2, 3)), daemon=True)
    try:
        thread.start()
    except RuntimeError:
        _SLOTS.release()
        raise TenantError("tenant_storage_unavailable", 503) from None
    try:
        success, result = results.get(timeout=max(0, deadline - time.monotonic()))
        if not success:
            if isinstance(result, transport.PrivateIntelligenceError):
                raise TenantError(result.code, result.status)
            raise TenantError("tenant_storage_unavailable", 503)
        return result
    except queue.Empty:
        raise TenantError("tenant_storage_unavailable", 503) from None
    finally:
        stopped.set()


def _principal_exists(principal):
    from services.auth_service import AuthService
    return AuthService._load_user_by_username(principal) is not None


class TenantStore:
    def __init__(self, *, call=None, principal_exists=None):
        self.call = call or private_call
        self.principal_exists = principal_exists or _principal_exists

    def request(self, operation, **values):
        if not enabled():
            raise TenantError("not_found", 404)
        if operation not in OPERATIONS:
            raise TenantError("invalid_request")
        if os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip() == "d1":
            return self._remote(operation, values)
        try:
            path = storage_path("AUTH_DB_PATH", "auth.sqlite3")
            if not path.is_file():
                raise TenantError("tenant_storage_unavailable", 503)
            with closing(connect(path)) as db:
                db.execute("BEGIN IMMEDIATE" if operation.endswith(("create", "update", "set")) else "BEGIN")
                # Verify all tables and columns before a mutation or a legacy resolution.
                for sql in ("SELECT id,name,status,revision FROM tenant_organisations LIMIT 0",
                            "SELECT id,org_id,name,status,revision FROM tenant_teams LIMIT 0",
                            "SELECT org_id,principal,team_id,role,status,revision FROM tenant_memberships LIMIT 0",
                            "SELECT principal,org_id,team_id,revision FROM tenant_bindings LIMIT 0",
                            "SELECT id,actor,action,org_id,team_id,principal,old_revision,new_revision,at FROM tenant_audit LIMIT 0"):
                    db.execute(sql)
                result = self._execute(db, operation, values)
                db.commit()
                return result
        except TenantError:
            raise
        except Exception:
            raise TenantError("tenant_storage_unavailable", 503) from None

    def _remote(self, operation, values):
        try:
            document = self.call({"version": 1, "operation": operation, **values})
            if not isinstance(document, dict) or document.get("version") != 1:
                raise ValueError()
            if "error" in document:
                code, status = document["error"]["code"], document["status"]
                if ERROR_STATUSES.get(code) != status:
                    raise ValueError()
                raise TenantError(code, status)
            result = document["result"]
            if not isinstance(result, dict):
                raise ValueError()
            return result
        except TenantError:
            raise
        except Exception:
            raise TenantError("tenant_storage_unavailable", 503) from None

    @staticmethod
    def _one(db, sql, params=()):
        row = db.execute(sql, params).fetchone()
        return dict(row) if row else None

    def _org(self, db, org_id, *, active=False):
        row = self._one(db, "SELECT * FROM tenant_organisations WHERE id=?", (_identifier(org_id),))
        if row is None:
            raise TenantError("workspace_not_found", 404)
        if active and row["status"] != "active":
            raise TenantError("workspace_forbidden", 403)
        return row

    def _team(self, db, org_id, team_id, *, active=False):
        row = self._one(db, "SELECT * FROM tenant_teams WHERE org_id=? AND id=?", (org_id, _identifier(team_id)))
        if row is None:
            raise TenantError("workspace_not_found", 404)
        if active and row["status"] != "active":
            raise TenantError("workspace_forbidden", 403)
        return row

    def _workspace(self, db, principal, org_id, team_id):
        org = self._org(db, org_id, active=True)
        team = self._team(db, org_id, team_id, active=True) if team_id is not None else None
        membership = self._one(db, "SELECT * FROM tenant_memberships WHERE org_id=? AND principal=?", (org_id, principal))
        if not membership or membership["status"] != "active" or membership["team_id"] != team_id:
            raise TenantError("workspace_forbidden", 403)
        return org["revision"] + (team["revision"] if team else 0) + membership["revision"]

    @staticmethod
    def _audit(db, actor, action, org_id, team_id, principal, old, new):
        db.execute("INSERT INTO tenant_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (uuid.uuid4().hex, _text(actor), action, org_id, team_id, principal, old, new,
                    datetime.now(timezone.utc).isoformat()))

    @staticmethod
    def _cas(row, revision):
        if (row["revision"] if row else 0) != _revision(revision):
            raise TenantError("revision_conflict", 412)

    def _execute(self, db, operation, v):
        if operation == "org_list":
            return {"organisations": [dict(row) for row in db.execute("SELECT * FROM tenant_organisations ORDER BY id")]}
        if operation in {"workspaces", "resolve", "binding_set"}:
            return self._principal_operation(db, operation, v)
        if operation == "org_create":
            return self._named_write(db, operation, v, None)
        org_id = v.get("org_id")
        org = self._org(db, org_id)
        if operation == "org_get":
            return org
        if operation in {"org_update", "team_create", "team_update"}:
            return self._named_write(db, operation, v, org)
        if operation == "team_list":
            return {"teams": [dict(row) for row in db.execute("SELECT * FROM tenant_teams WHERE org_id=? ORDER BY id", (org_id,))]}
        if operation == "member_list":
            return {"members": [dict(row) for row in db.execute("SELECT * FROM tenant_memberships WHERE org_id=? ORDER BY principal", (org_id,))]}
        return self._member_write(db, v)

    def _named_write(self, db, operation, v, org):
        data = v.get("data")
        creating, is_team = operation.endswith("create"), operation.startswith("team")
        if not isinstance(data, dict) or not data or set(data) - {"name", "status"}:
            raise TenantError("invalid_request")
        if creating and ("name" not in data or data.get("status", "active") != "active"):
            raise TenantError("invalid_request")
        if is_team and creating:
            self._org(db, v["org_id"], active=True)
            if db.execute("SELECT count(*) FROM tenant_teams WHERE org_id=?", (v["org_id"],)).fetchone()[0] >= 100:
                raise TenantError("tenant_limit_reached", 409)
        row = None if creating else self._team(db, v["org_id"], v["team_id"]) if is_team else org
        if not creating:
            self._cas(row, v.get("revision"))
        name = _text(data.get("name", row["name"] if row else None), 200)
        status = data.get("status", row["status"] if row else "active")
        if not isinstance(status, str) or status not in {"active", "deactivated"}:
            raise TenantError("invalid_request")
        identifier = uuid.uuid4().hex if creating else row["id"]
        old, new = (row["revision"] if row else 0), (row["revision"] + 1 if row else 1)
        if is_team:
            db.execute("INSERT INTO tenant_teams VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,status=excluded.status,revision=excluded.revision",
                       (identifier, v["org_id"], name, status, new))
        else:
            db.execute("INSERT INTO tenant_organisations VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,status=excluded.status,revision=excluded.revision",
                       (identifier, name, status, new))
        org_id, team_id = (v["org_id"], identifier) if is_team else (identifier, None)
        self._audit(db, v["actor"], operation, org_id, team_id, None, old, new)
        return self._team(db, org_id, team_id) if is_team else self._org(db, org_id)

    def _member_write(self, db, v):
        org_id, principal, data = v["org_id"], _text(v.get("principal")), v.get("data")
        if not isinstance(data, dict) or not data or set(data) - {"role", "team_id", "status", "bind", "binding_revision"}:
            raise TenantError("invalid_request")
        if not self.principal_exists(principal):
            raise TenantError("principal_not_found", 404)
        row = self._one(db, "SELECT * FROM tenant_memberships WHERE org_id=? AND principal=?", (org_id, principal))
        self._cas(row, v.get("revision"))
        if row is None and db.execute("SELECT count(*) FROM tenant_memberships WHERE org_id=?", (org_id,)).fetchone()[0] >= 1000:
            raise TenantError("tenant_limit_reached", 409)
        team_id = data.get("team_id", row["team_id"] if row else None)
        role, status = data.get("role", row["role"] if row else "member"), data.get("status", row["status"] if row else "active")
        if not isinstance(role, str) or role not in {"admin", "billing", "member"} or not isinstance(status, str) or status not in {"active", "deactivated"}:
            raise TenantError("invalid_request")
        if status == "active":
            self._org(db, org_id, active=True)
        if team_id is not None:
            self._team(db, org_id, team_id, active=status == "active")
        if "bind" in data and type(data["bind"]) is not bool:
            raise TenantError("invalid_request")
        if "binding_revision" in data and not data.get("bind"):
            raise TenantError("invalid_request")
        old = row["revision"] if row else 0
        db.execute("INSERT INTO tenant_memberships VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(org_id,principal) DO UPDATE SET team_id=excluded.team_id,role=excluded.role,status=excluded.status,revision=excluded.revision",
                   (org_id, principal, team_id, role, status, old + 1))
        self._audit(db, v["actor"], "member_set", org_id, team_id, principal, old, old + 1)
        if data.get("bind"):
            self._binding_write(db, principal, v["actor"], data.get("binding_revision"), {"org_id": org_id, "team_id": team_id})
        return self._one(db, "SELECT * FROM tenant_memberships WHERE org_id=? AND principal=?", (org_id, principal))

    def _principal_operation(self, db, operation, v):
        principal = _text(v.get("principal"))
        binding = self._one(db, "SELECT * FROM tenant_bindings WHERE principal=?", (principal,))
        if operation == "binding_set":
            if v.get("actor") != principal:
                raise TenantError("workspace_forbidden", 403)
            return self._binding_write(db, principal, principal, v.get("revision"), v.get("data"))
        if operation == "workspaces":
            rows = db.execute("SELECT m.* FROM tenant_memberships m JOIN tenant_organisations o ON o.id=m.org_id LEFT JOIN tenant_teams t ON t.id=m.team_id AND t.org_id=m.org_id WHERE m.principal=? AND m.status='active' AND o.status='active' AND (m.team_id IS NULL OR t.status='active') ORDER BY m.org_id", (principal,))
            return {"memberships": [dict(row) for row in rows], "binding": binding or {"principal": principal, "org_id": None, "team_id": None, "revision": 0}}
        if binding is None:
            return {"principal_id": _legacy(principal).principal_id, "org_id": None, "team_id": None, "grants_revision": 0}
        revision = self._workspace(db, principal, binding["org_id"], binding["team_id"])
        return {"principal_id": _legacy(principal).principal_id, "org_id": binding["org_id"], "team_id": binding["team_id"], "grants_revision": revision + binding["revision"]}

    def _binding_write(self, db, principal, actor, revision, data):
        if not isinstance(data, dict) or set(data) != {"org_id", "team_id"}:
            raise TenantError("invalid_request")
        self._workspace(db, principal, data["org_id"], data["team_id"])
        row = self._one(db, "SELECT * FROM tenant_bindings WHERE principal=?", (principal,))
        self._cas(row, revision)
        old = row["revision"] if row else 0
        db.execute("INSERT INTO tenant_bindings VALUES (?, ?, ?, ?) ON CONFLICT(principal) DO UPDATE SET org_id=excluded.org_id,team_id=excluded.team_id,revision=excluded.revision",
                   (principal, data["org_id"], data["team_id"], old + 1))
        self._audit(db, actor, "binding_set", data["org_id"], data["team_id"], principal, old, old + 1)
        return self._one(db, "SELECT * FROM tenant_bindings WHERE principal=?", (principal,))


def resolve_principal(principal, *, store=None):
    legacy = _legacy(principal)
    if not enabled():
        return legacy
    value = (store or TenantStore()).request("resolve", principal=principal)
    try:
        context = TenantContext(**value)
        if context.principal_id != legacy.principal_id:
            raise ValueError()
        return context
    except (ValueError, TypeError):
        raise TenantError("tenant_storage_unavailable", 503) from None


def current_tenant():
    if has_request_context() and hasattr(g, "tenant_context"):
        return g.tenant_context
    user = getattr(g, "authenticated_user", {}) if has_request_context() else {}
    return _legacy(user.get("username") or user.get("id") or "unknown")


def tenant_namespace(context=None):
    context = context or current_tenant()
    if context.org_id is None:
        return ""
    return "org:" + context.org_id + ("/team:" + context.team_id if context.team_id else "")


def tenant_context_hook():
    user = getattr(g, "authenticated_user", {})
    principal = user.get("username") or user.get("id") or "unknown"
    try:
        # Verified context was resolved just before usage metadata in authentication.
        verified = getattr(g, "verified_tenant", None)
        g.tenant_context = verified if verified and verified.principal_id == _legacy(principal).principal_id else resolve_principal(
            principal, store=current_app.extensions.get("tenant_store"))
    except TenantError as error:
        return error_response(error)
    return None


def verify_before_key_usage(principal):
    if enabled() and has_request_context():
        g.verified_tenant = resolve_principal(principal, store=current_app.extensions.get("tenant_store"))
