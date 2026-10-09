"""Strict SCIM resources and tenant-bound atomic persistence collaborators."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from functools import lru_cache

from error_handlers import APIError
from services.auth_primitives import build_api_key_prefix, hash_api_key, serialize_datetime, serialize_scopes
from services.enterprise_contract import AuthorityDenied, AuthorityOperation, TenantContext
from services.user_provisioning import provision_scim_user
from services.user_store import USER_FIELDS

logger = logging.getLogger(__name__)
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
MAX_BODY = 131072
USER_ATTRIBUTES = {"userName", "active", "displayName", "name", "emails", "externalId"}
GROUP_ATTRIBUTES = {"displayName", "externalId", "members"}
FILTER = re.compile(r'(userName|externalId|displayName) eq ("(?:[^"\\]|\\.)*")\Z')
MEMBER_PATH = re.compile(r'members\[value eq ("(?:[^"\\]|\\.)*")\]\Z')
REF = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


class ScimError(Exception):
    def __init__(self, status, detail, scim_type="invalidValue"):
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type

    def body(self):
        return {"schemas": [ERROR_SCHEMA], "status": str(self.status),
                "scimType": self.scim_type, "detail": self.detail}


@lru_cache(maxsize=1)
def _warn_once():
    logger.warning("Invalid SCIM_ENABLED; SCIM provisioning disabled")


def enabled(env=None):
    raw = (os.environ if env is None else env).get("SCIM_ENABLED", "")
    flag = raw.strip().lower() if isinstance(raw, str) else "invalid"
    if flag in {"", "0", "false", "off", "no"}:
        return False
    if flag in {"1", "true", "on", "yes"}:
        return True
    _warn_once()
    return False


def authenticate(authorization, env=None):
    """Only an unambiguous constant-time digest match establishes tenant scope."""
    env = os.environ if env is None else env
    if not isinstance(authorization, str) or not re.fullmatch(r"Bearer [^\s]{1,4096}", authorization, re.I):
        raise ScimError(401, "Provisioning bearer token required")
    presented = hashlib.sha256(authorization.split(" ", 1)[1].encode()).digest()
    try:
        config = json.loads(env.get("SCIM_TRUST_CONFIG_JSON", "") or "{}")
        if not isinstance(config, dict) or set(config) != {"tenants"} or not isinstance(config["tenants"], dict):
            raise ValueError()
        if len(config["tenants"]) > 1000:
            raise ValueError()
        matches = []
        for org, entry in config["tenants"].items():
            TenantContext("scim", org)
            if not isinstance(entry, dict) or set(entry) != {"token_ref"} or not isinstance(entry["token_ref"], str):
                raise ValueError()
            if not REF.fullmatch(entry["token_ref"]):
                raise ValueError()
            token = env.get(entry["token_ref"])
            if not isinstance(token, str) or not token or len(token) > 4096:
                continue
            if hmac.compare_digest(presented, hashlib.sha256(token.encode()).digest()):
                matches.append(org)
        if len(matches) != 1:
            raise ValueError()
        return matches[0], presented.hex()
    except (ValueError, TypeError, AttributeError):
        raise ScimError(401, "Provisioning bearer token not recognised") from None


def text(value, maximum=1024):
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        raise ScimError(400, "Invalid string attribute")
    return value


def validate_resource(body, kind):
    if not isinstance(body, dict):
        raise ScimError(400, "Resource must be an object", "invalidSyntax")
    attributes = USER_ATTRIBUTES if kind == "Users" else GROUP_ATTRIBUTES
    if set(body) - attributes - {"schemas", "id", "meta"}:
        raise ScimError(400, "Unsupported resource attribute")
    schema = USER_SCHEMA if kind == "Users" else GROUP_SCHEMA
    if "schemas" in body and body["schemas"] != [schema]:
        raise ScimError(400, "Unsupported resource schema")
    value = copy.deepcopy({key: item for key, item in body.items() if key in attributes})
    if "id" in body and not re.fullmatch(r"[a-f0-9]{32}", text(body["id"], 128)):
        raise ScimError(400, "Invalid resource id")
    if "meta" in body:
        meta = body["meta"]
        if not isinstance(meta, dict) or set(meta) - {"resourceType", "created", "lastModified", "location", "version"}:
            raise ScimError(400, "Unsupported metadata attribute")
        for item in meta.values():
            text(item)
    for key in ("externalId", "displayName"):
        if key in value:
            text(value[key])
    if kind == "Groups":
        text(value.get("displayName"))
        validate_members(value.setdefault("members", []))
        return value
    username = text(value.get("userName"), 128)
    if username.strip() != username:
        raise ScimError(400, "userName must not have surrounding whitespace")
    value.setdefault("active", True)
    if type(value["active"]) is not bool:
        raise ScimError(400, "active must be a boolean")
    if "name" in value:
        name = value["name"]
        if not isinstance(name, dict) or set(name) - {"formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"}:
            raise ScimError(400, "Unsupported name attribute")
        for item in name.values():
            text(item)
    if "emails" in value:
        emails = value["emails"]
        if not isinstance(emails, list) or len(emails) > 100:
            raise ScimError(400, "Invalid emails")
        primary = 0
        for email in emails:
            if not isinstance(email, dict) or set(email) - {"value", "type", "primary", "display"}:
                raise ScimError(400, "Unsupported email attribute")
            text(email.get("value"))
            for key in ("type", "display"):
                if key in email:
                    text(email[key])
            if "primary" in email and type(email["primary"]) is not bool:
                raise ScimError(400, "Invalid primary email flag")
            primary += email.get("primary", False)
        if primary > 1:
            raise ScimError(400, "Only one primary email is supported")
    return value


def validate_members(members):
    if not isinstance(members, list) or len(members) > 1000:
        raise ScimError(400, "Group membership limit is 1000")
    seen = set()
    for member in members:
        if not isinstance(member, dict) or set(member) - {"value", "display", "$ref"}:
            raise ScimError(400, "Unsupported member attribute")
        member_id = text(member.get("value"), 128)
        if member_id in seen:
            raise ScimError(400, "Duplicate group member")
        seen.add(member_id)
        for key in ("display", "$ref"):
            if key in member:
                text(member[key])


def pagination(args):
    try:
        start, count = args.get("startIndex", "1"), args.get("count", "100")
        if not re.fullmatch(r"[0-9]{1,9}", start) or not re.fullmatch(r"[0-9]{1,9}", count) or int(start) < 1:
            raise ValueError()
        return int(start), min(int(count), 100)
    except (TypeError, ValueError):
        raise ScimError(400, "Invalid pagination") from None


def parse_filter(expression):
    if expression is None:
        return None, None
    match = FILTER.fullmatch(expression) if len(expression) <= 2048 else None
    if not match:
        raise ScimError(400, "Only equality on userName, externalId or displayName is supported", "invalidFilter")
    try:
        return match[1], text(json.loads(match[2]))
    except (ValueError, TypeError):
        raise ScimError(400, "Invalid filter string", "invalidFilter") from None


def revision(resource):
    return int(resource["meta"]["version"][3:-1])


def match_version(resource, if_match):
    if if_match is not None and if_match not in {"*", resource["meta"]["version"]}:
        raise ScimError(412, "Resource version does not match")


def patch_resource(resource, body, kind):
    if (not isinstance(body, dict) or set(body) != {"schemas", "Operations"}
            or body["schemas"] != [PATCH_SCHEMA] or not isinstance(body["Operations"], list)
            or not 1 <= len(body["Operations"]) <= 100):
        raise ScimError(400, "Invalid PATCH document", "invalidSyntax")
    result = copy.deepcopy(resource)
    for operation in body["Operations"]:
        _patch_operation(result, operation, kind)
    return validate_resource(result, kind)


def _patch_operation(result, operation, kind):
    if not isinstance(operation, dict) or set(operation) - {"op", "path", "value"}:
        raise ScimError(400, "Invalid PATCH operation", "invalidSyntax")
    op, path = operation.get("op"), operation.get("path")
    if not isinstance(op, str) or op.lower() not in {"add", "replace", "remove"}:
        raise ScimError(400, "Unsupported PATCH operation", "invalidSyntax")
    op = op.lower()
    if path is None and op in {"add", "replace"} and isinstance(operation.get("value"), dict):
        for key, value in operation["value"].items():
            _patch_operation(result, {"op": op, "path": key, "value": value}, kind)
        return
    allowed = (USER_ATTRIBUTES - {"userName"}) if kind == "Users" else GROUP_ATTRIBUTES
    selector = MEMBER_PATH.fullmatch(path) if isinstance(path, str) and kind == "Groups" else None
    if selector and op == "remove":
        if "value" in operation:
            raise ScimError(400, "remove does not accept value", "invalidSyntax")
        try:
            member_id = text(json.loads(selector[1]), 128)
        except (TypeError, ValueError):
            raise ScimError(400, "Invalid member selector", "invalidSyntax") from None
        result["members"] = [member for member in result.get("members", []) if member["value"] != member_id]
        return
    if not isinstance(path, str) or path not in allowed:
        raise ScimError(400, "Unsupported PATCH path", "invalidSyntax")
    if op == "remove":
        if "value" in operation:
            raise ScimError(400, "remove does not accept value", "invalidSyntax")
        result.pop(path, None)
        if path == "active":
            result["active"] = False
        return
    if "value" not in operation:
        raise ScimError(400, "PATCH value required", "invalidSyntax")
    value = copy.deepcopy(operation["value"])
    if op == "add" and path in {"members", "emails"}:
        if not isinstance(value, list):
            raise ScimError(400, "Multi-valued attribute requires an array")
        value = result.get(path, []) + value
        if path == "members":
            unique = {}
            for member in value:
                validate_members([member])
                unique[member["value"]] = member
            value = list(unique.values())
    elif op == "add" and path == "name" and isinstance(value, dict):
        value = {**result.get(path, {}), **value}
    result[path] = value


def _account_row(**values):
    row = {key: None for key in USER_FIELDS}
    for key, value in values.items():
        if key == "controls":
            row.update(value or {})
        elif key == "scopes":
            row[key] = serialize_scopes(value)
        elif key == "is_admin":
            row[key] = int(value)
        elif key in USER_FIELDS:
            row[key] = serialize_datetime(value) if isinstance(value, datetime) else value
    return row


class D1ScimStore:
    """One-shot private RPC; storage failure never falls back to local accounts."""
    def __init__(self, call):
        self.call = call

    def _call(self, operation, **values):
        try:
            body = self.call({"version": 1, "operation": operation, **values})
        except Exception as error:
            status = getattr(error, "status", 503)
            if status in {400, 409, 412}:
                raise ScimError(status, "SCIM storage rejected the operation",
                                "uniqueness" if status == 409 else "invalidValue") from None
            raise ScimError(503, "SCIM storage is unavailable") from None
        if not isinstance(body, dict) or body.get("version") != 1 or "error" in body:
            raise ScimError(503, "Invalid SCIM storage response")
        return body

    def probe(self):
        if (os.environ.get("AUTH_STORAGE_BACKEND", "").strip().lower() != "d1"
                or os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip().lower() != "d1"
                or os.environ.get("CONFIG_REVISION_SYNC_ENABLED", "").strip().lower() not in {"true", "1", "yes", "on"}):
            raise ScimError(503, "SCIM requires durable accounts and security revision sync")
        self._call("probe")

    def get(self, org, kind, resource_id):
        return self._call("get", org_id=org, kind=kind, id=resource_id)["resource"]

    def account(self, username):
        return self._call("account", username=username)["account"]

    def list(self, org, kind, attribute=None, value=None, start=1, count=100):
        body = self._call("list", org_id=org, kind=kind, attribute=attribute, value=value, start=start, count=count)
        return body["resources"], body["total"]

    def put(self, org, kind, resource, expected, account=None, token_digest=None, deactivate=False):
        body = self._call("put", org_id=org, kind=kind, resource=resource, expected=expected,
                          account=account, token_digest=token_digest, deactivate=deactivate)
        return body["resource"], body["created"]


class ScimService:
    def __init__(self, store, auth, *, tenant_authority=None):
        self.store, self.auth, self.tenant_authority = store, auth, tenant_authority

    def ready(self):
        self.store.probe()

    def _group_scope(self, org, resource):
        if self.tenant_authority is None:
            raise ScimError(503, "Tenant authority unavailable")
        context = TenantContext("scim", org, resource["id"])
        operation = AuthorityOperation(context, resource["id"], revision(resource), uuid.uuid4().hex)
        try:
            granted = self.tenant_authority(operation)
        except AuthorityDenied:
            raise ScimError(503, "Tenant authority unavailable") from None
        if type(granted) is not TenantContext or granted != context:
            raise ScimError(403, "Tenant authority scope mismatch")
        for member in resource.get("members", []):
            user = self.store.get(org, "Users", member["value"])
            if user is None:
                raise ScimError(400, "Member must belong to this organisation")
            member_context = TenantContext(user["userName"], org)
            try:
                decision = self.tenant_authority(AuthorityOperation(member_context, member["value"], 0, uuid.uuid4().hex))
            except AuthorityDenied:
                raise ScimError(400, "Member must belong to this organisation") from None
            if type(decision) is not TenantContext or decision != member_context:
                raise ScimError(400, "Member must belong to this organisation")

    def get(self, org, kind, resource_id):
        self.ready()
        resource = self.store.get(org, kind, resource_id)
        if resource is None:
            raise ScimError(404, "Resource not found")
        return resource

    def list(self, org, kind, args):
        self.ready()
        if set(args) - {"filter", "startIndex", "count"}:
            raise ScimError(400, "Unsupported list parameter", "invalidSyntax")
        start, count = pagination(args)
        attribute, value = parse_filter(args.get("filter"))
        rows, total = self.store.list(org, kind, attribute, value, start, count)
        return {"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start,
                "itemsPerPage": len(rows), "Resources": rows}

    def create(self, org, kind, body, token_digest=None):
        self.ready()
        value = validate_resource(body, kind)
        if value.get("externalId"):
            rows, _ = self.store.list(org, kind, "externalId", value["externalId"], 1, 1)
            if rows:
                if kind == "Groups":
                    self._group_scope(org, rows[0])
                return rows[0], False
        resource = self._resource(value, kind)
        account = None
        if kind == "Users":
            prepared = []
            try:
                provision_scim_user(self.auth, value["userName"], active=value["active"],
                                    persist=lambda **data: prepared.append(_account_row(**data)))
            except APIError as error:
                if error.status_code == 409 and value.get("externalId"):
                    rows, _ = self.store.list(org, kind, "externalId", value["externalId"], 1, 1)
                    if rows:
                        return rows[0], False
                raise ScimError(error.status_code, "Account provisioning rejected",
                                "uniqueness" if error.status_code == 409 else "invalidValue") from None
            account = prepared[0]
        else:
            self._group_scope(org, resource)
        result = self.store.put(org, kind, resource, 0, account, token_digest)
        self.auth._forget_verified_keys()
        return result

    @staticmethod
    def _resource(value, kind, old=None):
        now = datetime.now(timezone.utc).isoformat()
        resource_id = old["id"] if old else uuid.uuid4().hex
        return {"schemas": [USER_SCHEMA if kind == "Users" else GROUP_SCHEMA], "id": resource_id, **value,
                "meta": {"resourceType": "User" if kind == "Users" else "Group",
                         "version": f'W/"{revision(old) + 1 if old else 1}"',
                         "created": old["meta"]["created"] if old else now, "lastModified": now,
                         "location": f"/scim/v2/{kind}/{resource_id}"}}

    def update(self, org, kind, resource_id, body, *, patch=False, delete=False, if_match=None, token_digest=None):
        old = self.get(org, kind, resource_id)
        match_version(old, if_match)
        if delete:
            value = validate_resource(old, kind)
            if kind == "Users":
                value["active"] = False
            else:
                value["members"] = []
        else:
            if isinstance(body, dict) and "id" in body and body["id"] != resource_id:
                raise ScimError(400, "id is immutable", "mutability")
            value = patch_resource(old, body, kind) if patch else validate_resource(body, kind)
        if kind == "Users" and value["userName"] != old["userName"]:
            raise ScimError(400, "userName is immutable", "mutability")
        resource = self._resource(value, kind, old)
        account = self._activation_account(old, resource) if kind == "Users" else None
        if kind == "Groups":
            self._group_scope(org, resource)
        saved, _ = self.store.put(org, kind, resource, revision(old), account, token_digest,
                                  deactivate=delete and kind == "Groups")
        self.auth._forget_verified_keys()
        return saved

    def _activation_account(self, old, resource):
        if old["active"] == resource["active"]:
            return None
        account = self.store.account(old["userName"])
        if not account or account["is_admin"] != 0:
            raise ScimError(503, "Provisioned account unavailable")
        if resource["active"] is False:
            key = self.auth._generate_api_key()
            # Sessions compare the short prefix; a collision must not resurrect them.
            if build_api_key_prefix(key) == account["api_key_prefix"]:
                key = ("A" if key[0] != "A" else "B") + key[1:]
            account.update(api_key_hash=hash_api_key(key), api_key_prefix=build_api_key_prefix(key),
                           revoked_at=datetime.now(timezone.utc).isoformat())
        else:
            account["revoked_at"] = None
        return account
