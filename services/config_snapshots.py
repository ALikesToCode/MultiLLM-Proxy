"""Bounded, configuration-only administration through the private D1 adapter."""
import hashlib
import json
import os
import re

from error_handlers import APIError
from services import auto_route_d1
from services.auto_route_service import AutoRouteService, DEFAULT_AUTO_ROUTES, LEGACY_DEFAULT_AUTO_ROUTES
from services.redaction import SECRET_TEXT_PATTERNS

MAX_SNAPSHOT_BYTES = 256 * 1024
MAX_ROUTES = 200
MAX_REVISION = 2**53 - 1
ACTOR = re.compile(r"[0-9a-f]{64}\Z")
TIMESTAMP = re.compile(r"[0-9T:.+\-Z]{10,40}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
CREDENTIAL_ID = re.compile(r"mllm_[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}")


def enabled():
    return os.environ.get("CONFIG_SNAPSHOTS_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def fail(message, status=400, code="invalid_config_snapshot"):
    raise APIError(message, status, {"error": code})


def revision(value):
    return type(value) is int and 0 <= value <= MAX_REVISION


def validate_configuration(value, base_urls):
    if not isinstance(value, dict) or set(value) != {"routes"}:
        fail("Only auto-route configuration is accepted")
    try:
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        fail("Invalid configuration")
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        fail("Snapshot exceeds 256 KiB", 413)
    rows = value["routes"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROUTES:
        fail("Snapshot must contain between 1 and 200 routes")
    routes, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"route_id", "candidates"}:
            fail("Only route IDs and candidate model IDs are accepted")
        try:
            route_id = AutoRouteService.normalize_route_id(row["route_id"])
            candidates = list(AutoRouteService.normalize_candidates(row["candidates"], base_urls))
        except ValueError:
            fail("Invalid route or candidate model ID")
        if tuple(candidates) in LEGACY_DEFAULT_AUTO_ROUTES.get(route_id, ()):
            fail("Retired seeded candidate orders cannot be applied; review the current model IDs")
        if route_id in seen:
            fail("Duplicate route ID")
        for identifier in [route_id, *candidates]:
            if CREDENTIAL_ID.search(identifier) or any(pattern.search(identifier) for pattern in SECRET_TEXT_PATTERNS):
                fail("Credential-shaped identifiers are not accepted")
        seen.add(route_id)
        routes.append({"route_id": route_id, "candidates": candidates})
    return {"routes": sorted(routes, key=lambda row: row["route_id"])}


def actor_identity(user):
    # Stable administrator attribution without storing usernames or account/key objects.
    name = user.get("username")
    if not isinstance(name, str) or not name:
        fail("Administrator identity is unavailable", 403)
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def call(operation, **values):
    if not enabled():
        fail("Not found", 404, "not_found")
    result = auto_route_d1.snapshot_request(operation, **values)
    if not valid_response(operation, result):
        fail("Snapshot storage returned an invalid response", 503, "config_snapshot_storage_unavailable")
    return result


def safe_identifier(value, pattern):
    return isinstance(value, str) and bool(pattern.fullmatch(value)) and not CREDENTIAL_ID.search(value) and not any(
        pattern.search(value) for pattern in SECRET_TEXT_PATTERNS)


def valid_metadata(row):
    return (isinstance(row, dict) and set(row) == {"id", "domain", "base_revision", "created_at", "created_by", "size_bytes"}
            and safe_identifier(row["id"], ID) and row["domain"] == "auto_routes" and revision(row["base_revision"])
            and safe_identifier(row["created_by"], ACTOR) and safe_identifier(row["created_at"], TIMESTAMP)
            and type(row["size_bytes"]) is int and 0 < row["size_bytes"] <= MAX_SNAPSHOT_BYTES)


def valid_audit(row):
    return (isinstance(row, dict) and set(row) == {"id", "snapshot_id", "base_revision", "revision", "applied_at", "applied_by"}
            and safe_identifier(row["id"], ID) and safe_identifier(row["snapshot_id"], ID)
            and revision(row["base_revision"]) and revision(row["revision"])
            and row["revision"] == row["base_revision"] + 1
            and safe_identifier(row["applied_by"], ACTOR) and safe_identifier(row["applied_at"], TIMESTAMP))


def valid_change(row):
    if not isinstance(row, dict) or set(row) != {"route_id", "before", "after"} or not safe_identifier(row["route_id"], auto_route_d1._ROUTE_ID):
        return False
    for name in ("before", "after"):
        models = row[name]
        if (not isinstance(models, list) or not (0 if name == "before" else 1) <= len(models) <= 16
                or not all(safe_identifier(model, auto_route_d1._MODEL_ID) for model in models)
                or len(set(models)) != len(models)):
            return False
    return True


def valid_response(operation, result):
    if operation == "snapshot_create":
        return set(result) == {"version", "snapshot"} and valid_metadata(result["snapshot"])
    if operation == "snapshot_apply":
        return (set(result) == {"version", "applied", "revision", "application_id"}
                and result["applied"] is True and revision(result["revision"]) and safe_identifier(result["application_id"], ID))
    if operation == "snapshot_list":
        return (set(result) == {"version", "domain", "current_revision", "snapshots", "applications"}
                and result["domain"] == "auto_routes" and revision(result["current_revision"])
                and isinstance(result["snapshots"], list) and len(result["snapshots"]) <= 100
                and all(valid_metadata(row) for row in result["snapshots"])
                and isinstance(result["applications"], list) and len(result["applications"]) <= 100
                and all(valid_audit(row) for row in result["applications"]))
    if operation == "snapshot_diff":
        return (set(result) == {"version", "id", "domain", "base_revision", "current_revision", "changes", "next_offset"}
                and safe_identifier(result["id"], ID) and result["domain"] == "auto_routes"
                and revision(result["base_revision"]) and revision(result["current_revision"])
                and isinstance(result["changes"], list) and len(result["changes"]) <= 20
                and all(valid_change(row) for row in result["changes"])
                and (result["next_offset"] is None or type(result["next_offset"]) is int and 0 < result["next_offset"] < MAX_ROUTES))
    return False


def create(body, user, base_urls):
    if not isinstance(body, dict) or set(body) != {"domain", "base_revision", "configuration"}:
        fail("Expected domain, base_revision and configuration")
    if body["domain"] != "auto_routes" or not revision(body["base_revision"]) or body["base_revision"] >= MAX_REVISION:
        fail("Invalid snapshot domain or base revision")
    configuration = validate_configuration(body["configuration"], base_urls)
    values = dict(domain="auto_routes", base_revision=body["base_revision"],
                  configuration=configuration, actor=actor_identity(user))
    # The existing private transport also bounds the complete envelope to 256 KiB.
    if len(json.dumps({"version": 1, "operation": "snapshot_create", **values}, separators=(",", ":")).encode()) > MAX_SNAPSHOT_BYTES:
        fail("Snapshot exceeds the private transport byte limit", 413)
    result = call("snapshot_create", **values)
    if result["snapshot"]["base_revision"] != body["base_revision"]:
        fail("Snapshot storage did not confirm the base revision", 503, "config_snapshot_storage_unavailable")
    return result


def diff(identifier, offset):
    if not ID.fullmatch(identifier):
        fail("Not found", 404, "not_found")
    if not isinstance(offset, str) or not offset.isascii() or not offset.isdecimal() or len(offset) > 3 or int(offset) > MAX_ROUTES:
        fail("Invalid diff offset")
    result = call("snapshot_diff", id=identifier, offset=int(offset))
    for change in result.get("changes", []):
        route_id = change["route_id"]
        before = tuple(change["before"])
        if route_id in DEFAULT_AUTO_ROUTES and (not before or before in LEGACY_DEFAULT_AUTO_ROUTES.get(route_id, ())):
            change["before"] = list(DEFAULT_AUTO_ROUTES[route_id])
    return result


def apply(identifier, body, user):
    if not ID.fullmatch(identifier):
        fail("Not found", 404, "not_found")
    if (not isinstance(body, dict) or set(body) != {"current_revision", "confirm"}
            or body.get("confirm") is not True or not revision(body.get("current_revision"))
            or body["current_revision"] >= MAX_REVISION):
        fail("Explicit confirm=true and current_revision are required", 409, "revision_conflict")
    result = call("snapshot_apply", id=identifier, current_revision=body["current_revision"],
                  confirm=True, actor=actor_identity(user))
    if result["revision"] != body["current_revision"] + 1:
        fail("Snapshot storage did not confirm the apply", 503, "config_snapshot_storage_unavailable")
    auto_route_d1.reset_cache()
    return result
