"""Owner-scoped immutable templates; rendering never dispatches generation."""

import hashlib
import json
import os
import queue
import re
import sqlite3
import threading
import time
from contextlib import closing

import requests
from requests.adapters import HTTPAdapter

from error_handlers import APIError
from services.connection_profiles import WorkbenchStore
from services.intelligence_d1_store import PrivateIntelligenceError

MAX_TEMPLATE_BYTES = 65536
MAX_VARIABLES = 32
MAX_RENDER_BYTES = 262144
MAX_BODY_BYTES = 524288
MAX_RESPONSE_BYTES = 1048576
MAX_VERSIONS = 100
PAGE_SIZE = 2
RETENTION_SECONDS = 30 * 86400
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
PLACEHOLDER = re.compile(r"{{([A-Za-z_][A-Za-z0-9_]{0,63})}}")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
PRIVATE_URL = "http://intelligence.internal/v1/state/prompt-templates"
_slots = threading.BoundedSemaphore(4)
SCHEMA = """CREATE TABLE IF NOT EXISTS prompt_templates (
    principal TEXT NOT NULL, slug TEXT NOT NULL, version INTEGER NOT NULL,
    content_hash TEXT NOT NULL, content TEXT NOT NULL, variables TEXT NOT NULL,
    created_at REAL NOT NULL, PRIMARY KEY (principal, slug, version))"""


def enabled():
    return os.environ.get("PROMPT_TEMPLATES_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def using_d1():
    backend = os.environ.get("INTELLIGENCE_STORAGE_BACKEND", "").strip()
    if backend not in {"", "d1"}:
        raise unavailable()
    return backend == "d1"


def invalid(message="Invalid prompt template fields"):
    return APIError(message, 400, {"error": "invalid_prompt_template"})


def unavailable():
    return APIError("Prompt template storage is unavailable; check migration 0014", 503,
                    {"error": "prompt_templates_storage_unavailable"})


def _bytes(value):
    if not isinstance(value, str):
        raise invalid("Template content and variable values must be strings")
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        raise invalid("Template text must be valid UTF-8") from None


def validate_identity(slug, version):
    if not isinstance(slug, str) or not SLUG.fullmatch(slug) or type(version) is not int or not 1 <= version <= 2147483647:
        raise invalid("Use a lowercase slug and a positive integer version")


def validate_template(value):
    required = {"slug", "version", "content", "variables"}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - {"content_hash"}:
        raise invalid()
    validate_identity(value["slug"], value["version"])
    content, variables = value["content"], value["variables"]
    if not 1 <= _bytes(content) <= MAX_TEMPLATE_BYTES:
        raise invalid("Template content must be between 1 byte and 64 KiB")
    if (not isinstance(variables, list) or len(variables) > MAX_VARIABLES
            or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in variables)
            or len(set(variables)) != len(variables)):
        raise invalid("Declare at most 32 unique variable names")
    remainder = PLACEHOLDER.sub("", content)
    if any(marker in remainder for marker in ("{{", "}}", "{%", "%}", "{#", "#}")):
        raise invalid("Only plain {{name}} placeholders are supported")
    if set(PLACEHOLDER.findall(content)) != set(variables):
        raise invalid("Declared variables must exactly match the placeholders")
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if "content_hash" in value and value["content_hash"] != digest:
        raise invalid("The content hash does not match the template")
    return {**{key: value[key] for key in ("slug", "version", "content")}, "variables": list(variables), "content_hash": digest}


def validate_cursor(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"slug", "version"}:
        raise invalid("Invalid template page cursor")
    validate_identity(value["slug"], value["version"])
    return dict(value)


def render_template(template, variables):
    template = validate_template(template)
    if not isinstance(variables, dict) or set(variables) != set(template["variables"]):
        raise invalid("Supply exactly the declared variables; missing and extra variables are refused")
    sizes = {name: _bytes(value) for name, value in variables.items()}
    if any(size > MAX_TEMPLATE_BYTES for size in sizes.values()) or sum(sizes.values()) > MAX_RENDER_BYTES:
        raise invalid("Variable values exceed the rendering limits")
    # Check expansion before allocating it. Replacement strings are never parsed again.
    size = _bytes(template["content"])
    for match in PLACEHOLDER.finditer(template["content"]):
        size += sizes[match.group(1)] - len(match.group(0))
    if size > MAX_RENDER_BYTES:
        raise APIError("Rendered content exceeds 256 KiB", 413, {"error": "prompt_render_too_large"})
    rendered = PLACEHOLDER.sub(lambda match: variables[match.group(1)], template["content"])
    return {"rendered": rendered, **{key: template[key] for key in ("slug", "version", "content_hash")}}


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON field")
        result[name] = value
    return result


def _submit(body, stopped, deadline, results):
    try:
        if stopped.is_set() or time.monotonic() >= deadline:
            raise unavailable()
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            with session.post(PRIVATE_URL, data=body, headers={"Content-Type": "application/json", "Accept": "application/json",
                              "Accept-Encoding": "identity"}, timeout=(2, 3), allow_redirects=False, stream=True) as response:
                if (response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                        or response.headers.get("Content-Encoding", "identity").lower() != "identity"):
                    raise unavailable()
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isascii() or not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES):
                    raise unavailable()
                data = bytearray()
                for chunk in response.iter_content(chunk_size=4096):
                    if stopped.is_set() or time.monotonic() >= deadline or len(data) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise unavailable()
                    data.extend(chunk)
                result = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
                if not isinstance(result, dict) or type(result.get("version")) is not int or result["version"] != 1:
                    raise unavailable()
                if response.status_code != 200:
                    code = (result.get("error") or {}).get("code")
                    if code not in {"version_conflict", "limit_reached", "storage_unavailable", "invalid_request", "not_found"}:
                        raise unavailable()
                    raise PrivateIntelligenceError(response.status_code, code)
                if "error" in result:
                    raise unavailable()
        results.put_nowait((True, result))
    except Exception as error:
        results.put_nowait((False, error if isinstance(error, PrivateIntelligenceError) else unavailable()))
    finally:
        _slots.release()


def d1_call(payload):
    """One fixed private submission, bounded to five seconds; no replay or disk fallback."""
    body = json.dumps({**payload, "version": 1}, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(body) > MAX_BODY_BYTES or not _slots.acquire(blocking=False):
        raise unavailable()
    stopped, results = threading.Event(), queue.Queue(maxsize=1)
    deadline = time.monotonic() + 5
    worker = threading.Thread(target=_submit, args=(body, stopped, deadline, results), daemon=True, name="prompt-template-store")
    try:
        worker.start()
    except Exception:
        _slots.release()
        raise unavailable() from None
    try:
        success, result = results.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        raise unavailable() from None
    finally:
        stopped.set()
    if not success:
        raise result from None
    return result


class PromptTemplateStore:
    """The workbench SQLite database locally, or the fixed private D1 domain."""

    @staticmethod
    def connection():
        return WorkbenchStore.connection()

    @staticmethod
    def ensure(connection):
        connection.execute(SCHEMA)
        connection.execute("CREATE INDEX IF NOT EXISTS prompt_templates_created ON prompt_templates (principal, created_at)")

    @staticmethod
    def _principal(value):
        if not isinstance(value, str) or not 1 <= len(value) <= 128 or CONTROL.search(value):
            raise APIError("An authenticated template owner is required", 403)
        return value

    @staticmethod
    def _d1(operation, principal, **values):
        try:
            response = d1_call({"operation": operation, "principal": principal, **values})
        except PrivateIntelligenceError as error:
            if error.status == 409 and error.code in {"version_conflict", "limit_reached"}:
                raise APIError("Template version already exists or owner version limit reached (100)", 409,
                               {"error": error.code}) from None
            raise unavailable() from None
        except Exception:
            raise unavailable() from None
        if not isinstance(response, dict) or type(response.get("version")) is not int or response["version"] != 1:
            raise unavailable()
        return response

    @staticmethod
    def _record(row):
        value = {key: row[key] for key in ("slug", "version", "content", "content_hash")}
        value["variables"] = json.loads(row["variables"])
        return PromptTemplateStore._checked(value)

    @classmethod
    def _checked(cls, value):
        try:
            if not isinstance(value, dict) or set(value) != {"slug", "version", "content", "variables", "content_hash"}:
                raise ValueError("Invalid template response")
            return validate_template(value)
        except (APIError, ValueError, TypeError):
            raise unavailable() from None

    @classmethod
    def create(cls, principal, value):
        principal, template = cls._principal(principal), validate_template(value)
        created_at = time.time()
        if using_d1():
            response = cls._d1("create", principal, template=template, created_at=created_at)
            if response != {"version": 1, "stored": True}:
                raise unavailable()
            return template
        try:
            with closing(cls.connection()) as db:
                db.execute("BEGIN IMMEDIATE")
                cls.ensure(db)
                if db.execute("SELECT 1 FROM prompt_templates WHERE principal = ? AND slug = ? AND version = ?",
                              (principal, template["slug"], template["version"])).fetchone():
                    raise APIError("Template version already exists", 409, {"error": "version_conflict"})
                if db.execute("SELECT COUNT(*) AS n FROM prompt_templates WHERE principal = ?", (principal,)).fetchone()["n"] >= MAX_VERSIONS:
                    raise APIError("Owner version limit reached (100)", 409, {"error": "limit_reached"})
                db.execute("INSERT INTO prompt_templates (principal, slug, version, content_hash, content, variables, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (principal, template["slug"], template["version"], template["content_hash"], template["content"], json.dumps(template["variables"]), created_at))
                db.commit()
        except (sqlite3.Error, OSError):
            raise unavailable() from None
        return template

    @classmethod
    def get(cls, principal, slug, version):
        principal = cls._principal(principal)
        validate_identity(slug, version)
        if using_d1():
            response = cls._d1("get", principal, slug=slug, template_version=version)
            if set(response) != {"version", "template"}:
                raise unavailable()
            row = response["template"]
            if row is not None:
                row = cls._checked(row)
                if (row["slug"], row["version"]) != (slug, version):
                    raise unavailable()
        else:
            try:
                with closing(cls.connection()) as db:
                    cls.ensure(db)
                    row = db.execute("SELECT * FROM prompt_templates WHERE principal = ? AND slug = ? AND version = ? AND created_at > ?",
                                     (principal, slug, version, time.time() - RETENTION_SECONDS)).fetchone()
                    db.commit()
                    row = cls._record(row) if row is not None else None
            except (sqlite3.Error, OSError, ValueError):
                raise unavailable() from None
        if row is None:
            raise APIError("Template version not found", 404, {"error": "prompt_template_not_found"})
        return row

    @classmethod
    def list(cls, principal, after=None):
        principal, after = cls._principal(principal), validate_cursor(after)
        if using_d1():
            response = cls._d1("list", principal, after=after)
            if set(response) != {"version", "templates", "next"} or not isinstance(response["templates"], list) or len(response["templates"]) > PAGE_SIZE:
                raise unavailable()
            try:
                rows = [cls._checked(row) for row in response["templates"]]
                following = validate_cursor(response["next"])
                keys = [(row["slug"], row["version"]) for row in rows]
                if keys != sorted(set(keys)) or (after and any(key <= (after["slug"], after["version"]) for key in keys)):
                    raise unavailable()
                if following and (len(rows) != PAGE_SIZE or following != {"slug": rows[-1]["slug"], "version": rows[-1]["version"]}):
                    raise unavailable()
            except APIError:
                raise unavailable() from None
            return {"templates": rows, "next": following}
        try:
            with closing(cls.connection()) as db:
                cls.ensure(db)
                cursor = after or {"slug": "", "version": 0}
                rows = db.execute("SELECT * FROM prompt_templates WHERE principal = ? AND created_at > ? AND (slug > ? OR (slug = ? AND version > ?)) ORDER BY slug, version LIMIT 3",
                                  (principal, time.time() - RETENTION_SECONDS, cursor["slug"], cursor["slug"], cursor["version"])).fetchall()
                db.commit()
                records = [cls._record(row) for row in rows[:PAGE_SIZE]]
        except (sqlite3.Error, OSError, ValueError):
            raise unavailable() from None
        following = {"slug": records[-1]["slug"], "version": records[-1]["version"]} if len(rows) > PAGE_SIZE else None
        return {"templates": records, "next": following}
