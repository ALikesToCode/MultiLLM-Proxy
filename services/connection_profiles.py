"""Validated connection settings and content-free comparison records."""

import json
import math
import re
import time
import uuid
from contextlib import closing

from error_handlers import APIError
from services.sqlite_store import connect, storage_path

PROVIDERS = {"nanogpt", "opencode", "openrouter", "linkapi", "navyai"}
MODES = {"provider-priority", "fastest-eligible", "quality", "pinned"}
EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
PROFILE_FIELDS = {"name", "kind", "provider", "model", "mode", "effort", "billing", "fallback", "memory", "recovery"}


def validate_profile(value):
    if not isinstance(value, dict) or set(value) != PROFILE_FIELDS:
        raise APIError("Profile must contain only the documented settings; credentials and URLs are not accepted", status_code=400)
    result = dict(value)
    for name in PROFILE_FIELDS:
        if not isinstance(result[name], str):
            raise APIError("Profile settings must be strings", status_code=400)
    if not re.fullmatch(r"[\w .()-]{1,64}", result["name"]):
        raise APIError("Use a short descriptive profile name", status_code=400)
    if result["kind"] not in {"roleplay", "direct"} or result["provider"] not in PROVIDERS | {""} or result["mode"] not in MODES:
        raise APIError("Invalid profile connection or routing mode", status_code=400)
    if result["effort"] not in EFFORTS or result["billing"] not in {"configured", "subscription-only"} or result["fallback"] not in {"safe", "none"} or result["memory"] not in {"auto", "off"}:
        raise APIError("Invalid effort, billing, fallback, or memory setting", status_code=400)
    if result["recovery"] not in {"on", "off"} or result["kind"] == "direct" and result["recovery"] != "off":
        raise APIError("Recovery is available only on roleplay connections", status_code=400)
    if not re.fullmatch(r"[A-Za-z0-9_./:-]{0,200}", result["model"]):
        raise APIError("Invalid model identifier", status_code=400)
    if result["mode"] == "pinned" and not (result["provider"] and result["model"]):
        raise APIError("Pinned profiles require a provider and model", status_code=400)
    if result["kind"] == "direct":
        if result["mode"] != "pinned" or result["fallback"] != "none" or result["memory"] != "off":
            raise APIError("Direct profiles require pinned routing, no fallback, and memory off", status_code=400)
        if result["billing"] == "subscription-only" and result["provider"] != "nanogpt":
            raise APIError("A hard subscription-only direct endpoint is available only for NanoGPT", status_code=400)
    return result


def routing_options(profile):
    return {field: profile[field] for field in ("mode", "provider", "model", "billing", "fallback")}


def profile_connection(profile, origin, wire_effort=None):
    if profile["kind"] == "roleplay":
        endpoint = "/roleplay/v1/chat/completions"
        body = {"model": "roleplay:auto", "routing": routing_options(profile),
                "reasoning_effort": profile["effort"], "memory": {"mode": profile["memory"]}, "stream": True,
                "recovery_enabled": profile["recovery"] == "on"}
        notes = "Use your proxy key. Routing restrictions are enforced by the roleplay endpoint."
    else:
        provider = profile["provider"]
        endpoint = "/openrouter/chat/completions" if provider == "openrouter" else f"/{provider}/v1/chat/completions"
        if provider == "nanogpt" and profile["billing"] == "subscription-only":
            endpoint = "/nanogpt/subscription/v1/chat/completions"
        body = {"model": profile["model"], "stream": True}
        if wire_effort and wire_effort != "native":
            body.update({"reasoning": {"effort": wire_effort}} if provider == "openrouter" else {"reasoning_effort": wire_effort})
        notes = "Direct routes do not provide roleplay memory or cross-provider fallback. Standard routes may use PAYG."
    return {"endpoint": origin + endpoint, "body": body, "authentication": "Supply your proxy key separately; no key is exported.", "notes": notes}


class WorkbenchStore:
    @staticmethod
    def connection():
        return connect(storage_path("CONNECTION_PROFILES_DB_PATH", "workbench.sqlite3"))

    @staticmethod
    def ensure(connection):
        connection.execute("CREATE TABLE IF NOT EXISTS connection_profiles (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, settings TEXT NOT NULL, created_at REAL NOT NULL)")
        connection.execute("CREATE TABLE IF NOT EXISTS comparison_results (id TEXT PRIMARY KEY, owner TEXT NOT NULL, created_at REAL NOT NULL, data TEXT NOT NULL)")

    @classmethod
    def profiles(cls, owner):
        with closing(cls.connection()) as connection:
            cls.ensure(connection)
            rows = connection.execute("SELECT id, settings, created_at FROM connection_profiles WHERE owner = ? ORDER BY created_at DESC", (owner,)).fetchall()
            connection.commit()
        return [{"id": row["id"], "created_at": row["created_at"], **json.loads(row["settings"])} for row in rows]

    @classmethod
    def save_profile(cls, owner, profile):
        profile = validate_profile(profile)
        identifier = uuid.uuid4().hex
        with closing(cls.connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cls.ensure(connection)
            count = connection.execute("SELECT COUNT(*) AS n FROM connection_profiles WHERE owner = ?", (owner,)).fetchone()["n"]
            if count >= 50:
                raise APIError("Profile limit reached (50); export or manage existing settings before adding more", status_code=409)
            connection.execute("INSERT INTO connection_profiles (id, owner, name, settings, created_at) VALUES (?, ?, ?, ?, ?)",
                               (identifier, owner, profile["name"], json.dumps(profile), time.time()))
            connection.commit()
        return identifier

    @classmethod
    def save_report(cls, owner, rows):
        if not isinstance(rows, list) or not 2 <= len(rows) <= 12:
            raise APIError("A comparison requires 2-12 measured runs", status_code=400)
        fields = {"provider", "model", "case", "effort", "status", "rating", "ttft_ms", "duration_ms", "output_tokens", "tps"}
        for row in rows:
            if not isinstance(row, dict) or set(row) != fields or any(not isinstance(row[key], str) for key in ("provider", "model", "case", "effort", "status")) or row["provider"] not in PROVIDERS or row["effort"] not in EFFORTS:
                raise APIError("Invalid comparison record; only content-free measurements are accepted", status_code=400)
            from services.comparison_lab import SCENES
            if row["case"] not in SCENES or row["status"] not in {"completed", "interrupted", "failed", "cancelled"}:
                raise APIError("Invalid comparison scene or status", status_code=400)
            if not isinstance(row["model"], str) or not re.fullmatch(r"[A-Za-z0-9_./:-]{1,200}", row["model"]):
                raise APIError("Invalid comparison model", status_code=400)
            if type(row["rating"]) is not int or not 1 <= row["rating"] <= 5:
                raise APIError("Rate each blind answer from 1 to 5 before saving", status_code=400)
            for field in ("ttft_ms", "duration_ms", "output_tokens", "tps"):
                value = row[field]
                if value is not None and (type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 10_000_000):
                    raise APIError("Invalid comparison measurement", status_code=400)
        with closing(cls.connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            cls.ensure(connection)
            if connection.execute("SELECT COUNT(*) AS n FROM comparison_results WHERE owner = ?", (owner,)).fetchone()["n"] >= 100:
                raise APIError("Comparison history limit reached (100)", status_code=409)
            identifier = uuid.uuid4().hex
            connection.execute("INSERT INTO comparison_results (id, owner, created_at, data) VALUES (?, ?, ?, ?)",
                               (identifier, owner, time.time(), json.dumps(rows, allow_nan=False)))
            connection.commit()
        return identifier

    @classmethod
    def reports(cls, owner):
        with closing(cls.connection()) as connection:
            cls.ensure(connection)
            rows = connection.execute("SELECT id, created_at, data FROM comparison_results WHERE owner = ? ORDER BY created_at DESC LIMIT 100", (owner,)).fetchall()
            connection.commit()
        return [{"id": row["id"], "created_at": row["created_at"], "measurements": json.loads(row["data"]),
                 "measurement_source": "browser-observed timing and provider-reported token usage; human quality ratings"} for row in rows]
