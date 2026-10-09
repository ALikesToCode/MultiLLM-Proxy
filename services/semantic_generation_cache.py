"""Explicitly scoped semantic reuse with bounded paid embeddings and private storage."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import queue
import re
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable

import requests
from requests.adapters import HTTPAdapter
from flask import Response, after_this_request, current_app, g, request

from services.cost_service import CostService
from services import cache_policy, shared_generation_cache as exact
from services.retention_policy import request_policy

MAX_TOKENS = 1024
MAX_COST = 0.001
MAX_RPC_BYTES = 2 * 1024 * 1024
ENDPOINT = "http://intelligence.internal/v1/state/semantic-cache"
_SLOTS = threading.BoundedSemaphore(4)
_MODEL = re.compile(r"[a-z][a-z0-9-]*:[A-Za-z0-9@][A-Za-z0-9._:/+@-]{0,255}\Z")
_VOLATILE = re.compile(r"\b(?:today|tomorrow|yesterday|now|current|latest|live|weather|stock|real.?time)\b", re.I)
_FACTS = re.compile(r"[-+]?\d+(?:[.,:/-]\d+)*|\b(?:no|not|never|without|cannot|neither|nor|nothing|nobody|none)\b|\b\w+n['’]t\b", re.I)
_DATE_NUMBERS = re.compile(r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:rs(?:day)?)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|billion|trillion|first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth)\b", re.I)
_QUOTES = re.compile(r'''"[^"\n]*"|(?<!\w)'[^'\n]*'|“[^”\n]*”|‘[^’\n]*’''')
logger = logging.getLogger(__name__)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@lru_cache(maxsize=4)
def _warn_once(event):
    logger.warning("Semantic generation cache %s", event)


@dataclass(frozen=True)
class Settings:
    enabled: bool = False
    policy: dict | None = None


def settings(env=None):
    env = os.environ if env is None else env
    flag = str(env.get("SEMANTIC_CACHE_ENABLED", "")).strip().lower()
    if flag in {"", "false", "0", "no", "off"}:
        return Settings(False, {})
    try:
        if flag not in {"true", "1", "yes", "on"}:
            raise ValueError("invalid_setting")
        policy = json.loads(str(env.get("SEMANTIC_CACHE_POLICY_JSON", "")).strip() or "{}")
        if (not isinstance(policy, dict) or set(policy) - {"routes", "keys", "embedding_model", "revision", "model_revision", "allow_tools", "allow_streams"}
                or any(policy.get(k, False) is not False for k in ("allow_tools", "allow_streams"))):
            raise ValueError("invalid_setting")
        for key in ("routes", "keys"):
            if not isinstance(policy.get(key, []), list) or not all(isinstance(v, str) and 0 < len(v) <= 256 for v in policy.get(key, [])):
                raise ValueError("invalid_setting")
        if policy.get("routes") or policy.get("keys"):
            if not isinstance(policy.get("embedding_model"), str) or not _MODEL.fullmatch(policy["embedding_model"]):
                raise ValueError("invalid_setting")
        for key in ("revision", "model_revision"):
            if key in policy and (not isinstance(policy[key], str) or not 0 < len(policy[key]) <= 256):
                raise ValueError("invalid_setting")
        return Settings(True, policy)
    except (ValueError, TypeError, RecursionError):
        _warn_once("invalid_configuration")
        return Settings(False, {})


def eligible(payload):
    if (not isinstance(payload, dict) or not isinstance(payload.get("model"), str)
            or not _MODEL.fullmatch(payload["model"]) or payload["model"].startswith(("auto:", "free:", "cascade:"))
            or payload.get("stream") or payload.get("n", 1) != 1 or "routing" in payload
            or any(payload.get(k) for k in ("tools", "functions", "tool_choice", "function_call"))):
        return False
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages or not isinstance(messages[-1], dict):
        return False
    if any(not isinstance(m, dict) or m.get("role") not in {"user", "system", "assistant", "developer"}
           or any(m.get(k) for k in ("tool_calls", "function_call", "tool_call_id")) for m in messages):
        return False
    text = messages[-1].get("content")
    return (messages[-1].get("role") == "user" and isinstance(text, str) and bool(text.strip())
            and len(text.encode("utf-8")) <= MAX_TOKENS * 4 and not _VOLATILE.search(text))


def guard_hash(text):
    return digest(canonical([_FACTS.findall(text.lower()), _DATE_NUMBERS.findall(text.lower()), _QUOTES.findall(text)]))


def vector_valid(value):
    return (isinstance(value, list) and 1 <= len(value) <= 8192
            and all(type(v) in (int, float) and math.isfinite(v) for v in value)
            and math.isfinite(sum(v * v for v in value)) and sum(v * v for v in value) > 0)


def cosine(one, two):
    if not vector_valid(one) or not vector_valid(two) or len(one) != len(two):
        return -1
    return sum(a * b for a, b in zip(one, two)) / math.sqrt(sum(a * a for a in one)) / math.sqrt(sum(b * b for b in two))


def partition(principal, path, payload, revisions, policy):
    messages = [*payload["messages"][:-1], {**payload["messages"][-1], "content": None}]
    invariant = {**payload, "messages": messages}
    return {"principal_hash": digest(principal),
            "partition_hash": digest(canonical([path, invariant, revisions, policy])),
            "model_revision": digest(canonical([policy.get("embedding_model"), policy.get("model_revision", "1")]))}


class SemanticCacheSchemaMissing(Exception):
    """Deployment has not provided the required durable schema."""


def _exchange(encoded, results, stopped, deadline):
    result = None
    try:
        with requests.Session() as session:
            session.trust_env = False
            session.mount("http://", HTTPAdapter(max_retries=0))
            with session.post(ENDPOINT, data=encoded, headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
                              timeout=(1, 2), allow_redirects=False, stream=True) as response:
                data = bytearray()
                if response.headers.get("Content-Encoding", "identity") != "identity":
                    raise ValueError("cache_transport_unavailable")
                for chunk in response.iter_content(chunk_size=4096):
                    if stopped.is_set() or time.monotonic() >= deadline or len(data) + len(chunk) > MAX_RPC_BYTES:
                        raise ValueError("cache_transport_unavailable")
                    data.extend(chunk)
                value = json.loads(data)
                if response.status_code == 503 and value.get("error") == "semantic_cache_schema_missing":
                    result = SemanticCacheSchemaMissing()
                elif response.status_code == 200 and value.get("version") == 1:
                    result = value
    except Exception:
        pass
    finally:
        results.put_nowait(result)
        _SLOTS.release()


def private_transport(value):
    encoded = canonical({**value, "version": 1}).encode()
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
        result = results.get(timeout=3)
        if isinstance(result, SemanticCacheSchemaMissing):
            raise result
        return result
    except queue.Empty:
        return None
    finally:
        stopped.set()


class SemanticGenerationCache:
    """D1 metadata and scoped R2 bodies over one fixed private operation set."""
    def __init__(self, transport=None):
        self.transport = transport or private_transport

    def call(self, operation, **values):
        result = self.transport({"version": 1, "operation": operation, **values})
        if not isinstance(result, dict) or result.get("version") != 1 or "error" in result:
            raise ValueError("semantic_cache_unavailable")
        return result

    def ready(self):
        if self.call("ready").get("ready") is not True:
            raise ValueError("semantic_cache_unavailable")

    def scan(self, identity, vector, guard):
        rows = self.call("scan", **identity, vector=vector, guard_hash=guard).get("rows")
        if not isinstance(rows, list) or len(rows) > 256:
            raise ValueError("semantic_cache_unavailable")
        return rows

    def body(self, identity, row):
        entry = self.call("body", **identity, entry_id=row["entry_id"]).get("entry")
        if not isinstance(entry, dict) or not exact.valid_metadata(entry.get("metadata")):
            return None
        age, encoded = entry.get("age"), entry.get("body")
        if type(age) not in (int, float) or not 0 <= age < 300 or not isinstance(encoded, str) or len(encoded) > 1398104:
            return None
        body = base64.b64decode(encoded, validate=True)
        if len(body) > exact.MAX_BODY_BYTES or not exact.complete_body(body):
            return None
        return body, entry["metadata"], age

    def put(self, identity, vector, guard, body, metadata):
        return self.call("put", **identity, vector=vector, guard_hash=guard,
                         body=base64.b64encode(body).decode("ascii"), metadata=metadata).get("stored") is True


def embedding_allowed(model):
    from services.key_controls import model_allowed
    return model_allowed(getattr(g, "authenticated_user", {}) or {}, model)


def embedding_preflight(model, text):
    from routes.media_audio import MediaRequest, OPERATIONS, validate_media_candidate
    from services.auth_service import AuthService
    media = MediaRequest(OPERATIONS["embeddings"], model, {"input": text, "encoding_format": "float"})
    validate_media_candidate(current_app, AuthService, media, model)
    return media


def configured_embedding(model, text, media=None):
    """Use the existing configured embedding route, without generation warmup."""
    from routes.media_audio import dispatch_media_candidate
    from services.auth_service import AuthService
    from services.metrics_service import MetricsService
    from services.proxy_service import ProxyService
    media = media or embedding_preflight(model, text)
    response = dispatch_media_candidate(current_app, AuthService, MetricsService, ProxyService, media, model)
    try:
        body = bytearray()
        for chunk in response.iter_encoded():
            body.extend(chunk)
            if len(body) > 262144:
                raise ValueError("embedding_response_too_large")
        if response.status_code != 200:
            raise ValueError("embedding_failed")
        return json.loads(body)
    finally:
        response.close()


def embed_accounted(model, text, price):
    from services import request_accounting as accounting
    from services.prompt_cache_cost import CacheObservation
    from services.usage_types import UsageObservation
    embed = current_app.extensions.get("semantic_cache_embedding", configured_embedding)
    media = embedding_preflight(model, text) if embed is configured_embedding else None
    user = getattr(g, "authenticated_user", {}) or {}
    context = accounting.UsageContext(kind="embeddings", models=[model], provider=model.split(":", 1)[0],
        user=user, started=time.perf_counter(), start_ns=time.time_ns(), units=1,
        trace=accounting.telemetry_export.trace_context(request.headers.get("traceparent")))
    context.path, context.method = "/v1/embeddings", "POST"
    context.input_tokens, context.output_tokens = MAX_TOKENS, 0
    if accounting.budgeted(user):
        decision = accounting.BudgetService.check_and_reserve(user, price)
        if not decision.allowed:
            return None
        context.reservation = decision.reservation
    usage, status = CacheObservation(MAX_TOKENS, 0, "estimated", ("request_estimate",)), 502
    try:
        accounting.BudgetService.mark_dispatched(context.reservation)
        result = embed(model, text, media) if media is not None else embed(model, text)
        observed = result.get("usage") if isinstance(result, dict) else None
        tokens = observed.get("prompt_tokens", observed.get("input_tokens")) if isinstance(observed, dict) else None
        if type(tokens) is int and 0 <= tokens <= 2**53 - 1:
            usage = UsageObservation(tokens, 0, "provider", ("provider",))
        vector = result["data"][0]["embedding"] if isinstance(result, dict) else result
        status = 200 if vector_valid(vector) else 502
        return vector if vector_valid(vector) else None
    finally:
        accounting._record(context, status, usage, None)


@dataclass
class PreparedSemanticCache:
    store: Any
    identity: dict
    vector: list
    guard: str
    current: Callable[[], dict | None]

    def lookup(self):
        try:
            rows = self.store.scan(self.identity, self.vector, self.guard)
            candidates = [row for row in rows if row.get("guard_hash") == self.guard
                          and cosine(self.vector, row.get("vector")) >= 0.98]
            candidates.sort(key=lambda row: cosine(self.vector, row["vector"]), reverse=True)
            for row in candidates:
                entry = self.store.body(self.identity, row)
                if entry is not None and self.current() == self.identity:
                    return entry
        except SemanticCacheSchemaMissing:
            raise
        except Exception:
            _warn_once("storage_unavailable")
        return None

    def save(self, response, metadata):
        from services.managed_turn import cache_response_allowed
        try:
            if (response.status_code != 200 or response.is_streamed or response.direct_passthrough
                    or response.mimetype != "application/json" or not cache_response_allowed(response)
                    or "no-store" in response.headers.get("Cache-Control", "").lower()):
                return
            body = response.get_data()
            if len(body) <= exact.MAX_BODY_BYTES and exact.complete_body(body) and self.current() == self.identity:
                self.store.put(self.identity, self.vector, self.guard, body, metadata)
        except Exception:
            _warn_once("storage_unavailable")


def prepare_request(payload, principal):
    config, retention = settings(), request_policy()
    policy = config.policy or {}
    user = getattr(g, "authenticated_user", {}) or {}
    key_scope = str(user.get("id") or user.get("username") or "")
    if (not config.enabled or not principal or request.method != "POST" or not retention.allows_content
            or request.path not in policy.get("routes", []) and key_scope not in policy.get("keys", [])
            or not eligible(payload) or "no-store" in request.headers.get("Cache-Control", "").lower()):
        return None
    model = policy["embedding_model"]
    price = CostService.estimate(model, MAX_TOKENS, 0)
    if price is None or not math.isfinite(price) or not 0 <= price <= MAX_COST or not embedding_allowed(model):
        return None
    def current():
        resolved = exact.shared_policy(payload)
        if resolved is None or settings() != config or not embedding_allowed(model):
            return None
        return partition(principal, request.path, payload,
            {"policy": cache_policy.policy_digest(resolved), "retention": retention.revision,
             "retention_config": os.environ.get("CONTENT_RETENTION_POLICY_JSON", ""),
             "retention_enabled": os.environ.get("CONTENT_RETENTION_ENABLED", ""),
             "headers": {key: request.headers.get(key) for key in ("openai-organization", "openai-project",
                         "openai-beta", "anthropic-version", "anthropic-beta")}}, policy)
    identity = current()
    if identity is None:
        return None
    from services.cache_service import semantic_response_cache
    store = semantic_response_cache()
    try:
        store.ready()
        vector = embed_accounted(model, payload["messages"][-1]["content"], price)
        if vector is None:
            return None
        return PreparedSemanticCache(store, identity, vector, guard_hash(payload["messages"][-1]["content"]), current)
    except SemanticCacheSchemaMissing:
        raise
    except Exception:
        _warn_once("storage_unavailable")
        return None


def semantic_hit(entry):
    """Accounting consumes the existing hit marker before Flask emits distinct provenance."""
    body, metadata, age = entry
    response = Response(body, content_type="application/json")
    for name, value in metadata["headers"].items():
        response.headers[name] = value
    response.headers["X-MultiLLM-Cache"] = "hit"
    response.headers["X-MultiLLM-Cache-Backend"] = "semantic-d1-r2"
    response.headers["X-MultiLLM-Usage-Basis"] = "cache-served"
    response.headers["X-MultiLLM-Provider-Calls"] = "0"
    response.headers["Age"] = str(int(age))
    g.multillm_provider, g.multillm_model = metadata["provider"], metadata["model"]
    g.multillm_route_decision = "semantic-cache-hit"
    @after_this_request
    def provenance(result):
        result.headers["X-MultiLLM-Cache"] = "semantic-hit"
        return result
    return response
