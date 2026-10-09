"""Opt-in shared exact response adapter over the fixed private Worker endpoint."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import queue
import threading
import time
from functools import lru_cache

import requests
from flask import g, request
from requests.adapters import HTTPAdapter

from services import cache_policy
from services.retention_policy import request_policy

MAX_BODY_BYTES = 1024 * 1024
MAX_RPC_BYTES = 1_500_000
TTL_SECONDS = 300
ENDPOINT = "http://intelligence.internal/v1/state/generation-cache"
_HEADERS = frozenset({"X-MultiLLM-Auto-Route", "X-MultiLLM-Auto-Selected-Model",
    "X-MultiLLM-Auto-Selected-Priority", "X-MultiLLM-Cascade", "X-MultiLLM-Auto-Ordering",
    "X-MultiLLM-Prompt-Cache", "X-MultiLLM-Prompt-Cache-Mode"})
_SLOTS = threading.BoundedSemaphore(4)
logger = logging.getLogger(__name__)


@lru_cache(maxsize=8)
def _warn_once(event):
    logger.warning("Shared generation cache %s", event)


def shared_enabled(env=None):
    env = os.environ if env is None else env
    backend = env.get("GENERATION_CACHE_BACKEND", "").strip() or "memory"
    flag = env.get("GENERATION_CACHE_SHARED_ENABLED", "").strip().lower()
    if backend not in {"memory", "d1-r2"}:
        _warn_once("invalid_backend")
        return False
    if flag not in {"", "false", "0", "no", "off", "true", "1", "yes", "on"}:
        _warn_once("invalid_enabled_setting")
        return False
    return backend == "d1-r2" and flag in {"true", "1", "yes", "on"}


def shared_policy(payload):
    """Resolve server policy even when legacy memory identity is selected."""
    retention = request_policy()
    if not retention.allows_content:
        return None
    if not retention.enabled:
        return cache_policy.resolve_policy(payload)
    try:
        # The legacy resolver deliberately rejects prospective retention modes.
        # Build the same route/grant snapshot with this request's immutable policy.
        from services.key_controls import model_patterns
        from services.secret_firewall import scan_mode
        from flask import current_app
        if request.query_string or any(request.headers.get(name) for name in
                ("X-Provider", "X-Model", "X-MultiLLM-Provider")):
            return None
        route = cache_policy._resolved_route(payload["model"])
        if route is None:
            return None
        route["workflow_settings"] = {
            "config": {name: current_app.config.get(name) for name in cache_policy._WORKFLOW_CONFIG},
            "environment": {name: os.environ.get(name) for name in cache_policy._WORKFLOW_ENV}}
        user = getattr(g, "authenticated_user", None) or {}
        patterns = model_patterns(user)
        workflow = getattr(g, "multillm_workflow_version", cache_policy.WORKFLOW_VERSION)
        if not isinstance(workflow, str) or not workflow:
            return None
        policy = cache_policy.CachePolicy(route, sorted({p.lower() for p in patterns}) if patterns else None,
            scan_mode(user), {"mode": retention.mode, "revision": retention.revision}, workflow)
        cache_policy.policy_digest(policy)
        return policy
    except Exception:
        return None


def valid_metadata(value):
    return (isinstance(value, dict) and set(value) == {"content_type", "headers", "provider", "model"}
        and value["content_type"] == "application/json"
        and isinstance(value["headers"], dict) and not set(value["headers"]) - _HEADERS
        and all(isinstance(v, str) and len(v) <= 1024 and not any(ord(c) < 32 or ord(c) == 127 for c in v)
                for v in value["headers"].values())
        and all(value[k] is None or isinstance(value[k], str) and len(value[k]) <= 256
                and not any(ord(c) < 32 or ord(c) == 127 for c in value[k]) for k in ("provider", "model")))


def complete_body(body):
    try:
        value = json.loads(body)
        choices = value.get("choices") if isinstance(value, dict) and "error" not in value else None
        return (isinstance(choices, list) and len(choices) == 1
            and isinstance(choices[0], dict) and choices[0].get("finish_reason") in {"stop", "end_turn", "stop_sequence", "eos"}
            and isinstance(choices[0].get("message"), dict) and not choices[0]["message"].get("tool_calls")
            and not choices[0]["message"].get("function_call"))
    except (ValueError, UnicodeError, RecursionError):
        return False


def _exchange(encoded, results, stopped, deadline):
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            if stopped.is_set():
                return
            with session.post(ENDPOINT, data=encoded, headers={"Content-Type": "application/json",
                    "Accept": "application/json", "Accept-Encoding": "identity"}, timeout=(1, 2),
                    allow_redirects=False, stream=True) as response:
                if response.status_code != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                    raise ValueError("cache_unavailable")
                if response.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json":
                    raise ValueError("cache_unavailable")
                data = bytearray()
                for chunk in response.iter_content(chunk_size=4096):
                    if stopped.is_set() or time.monotonic() >= deadline or len(data) + len(chunk) > MAX_RPC_BYTES:
                        raise ValueError("cache_unavailable")
                    data.extend(chunk)
                value = json.loads(data)
                if not isinstance(value, dict) or value.get("version") != 1 or "error" in value:
                    raise ValueError("cache_unavailable")
                results.put_nowait(value)
    except Exception:
        results.put_nowait(None)
    finally:
        _SLOTS.release()


def private_transport(value):
    """Single submission with bounded wait, body, concurrency and no redirects."""
    encoded = json.dumps({**value, "version": 1}, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > MAX_RPC_BYTES or not _SLOTS.acquire(blocking=False):
        return None
    results, stopped = queue.Queue(maxsize=1), threading.Event()
    deadline = time.monotonic() + 3
    worker = threading.Thread(target=_exchange, args=(encoded, results, stopped, deadline), daemon=True)
    try:
        worker.start()
    except Exception:
        _SLOTS.release()
        return None
    try:
        return results.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        return None
    finally:
        stopped.set()


class SharedGenerationCache:
    """Bodies cross the private transport; keys contain only digested identities."""
    def __init__(self, transport=None):
        self.transport = transport or private_transport

    def _call(self, value):
        try:
            response = self.transport({"version": 1, **value})
            if isinstance(response, dict) and response.get("version") == 1 and "error" not in response:
                return response
        except Exception:
            pass
        _warn_once("storage_unavailable")
        return {}

    def get(self, key, *, principal_hash, policy_hash, model, max_age=None):
        response = self._call(dict(operation="get", cache_key=key, principal_hash=principal_hash,
            policy_hash=policy_hash, model=model, max_age=max_age))
        entry = response.get("entry")
        if not isinstance(entry, dict) or not valid_metadata(entry.get("metadata")):
            return None
        age, encoded = entry.get("age"), entry.get("body")
        if (type(age) not in (int, float) or not 0 <= age < TTL_SECONDS or
                max_age is not None and age > max_age or not isinstance(encoded, str)
                or len(encoded) > ((MAX_BODY_BYTES + 2) // 3) * 4):
            return None
        try:
            body = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError):
            return None
        if len(body) > MAX_BODY_BYTES or not complete_body(body):
            return None
        return body, entry["metadata"], age

    def put(self, key, body, metadata, *, principal_hash, policy_hash, model):
        if len(body) > MAX_BODY_BYTES or not valid_metadata(metadata) or not complete_body(body):
            return False
        response = self._call(dict(operation="put", cache_key=key, principal_hash=principal_hash,
            policy_hash=policy_hash, model=model, body=base64.b64encode(body).decode("ascii"), metadata=metadata))
        return response.get("stored") is True


def namespace_principal(principal, context=None):
    from services.tenant_hierarchy import tenant_namespace
    namespace = tenant_namespace(context)
    return namespace + "\0" + principal if namespace else principal


def identity(principal, payload, policy):
    principal = namespace_principal(principal)
    return {"principal_hash": hashlib.sha256(principal.encode()).hexdigest(),
            "policy_hash": cache_policy.policy_digest(policy), "model": payload["model"]}
