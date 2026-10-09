"""Bounded outcome affinity; eligibility and fallback remain caller-owned."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from functools import wraps
from typing import Callable

from flask import current_app, g, has_request_context, request

from services.opencode_session import reusable_prefix_digest
from services.upstream_outcome import UpstreamOutcome

logger = logging.getLogger(__name__)
MAX_ENTRIES = 10_000
_warned: set[str] = set()
_active: ContextVar[AffinityScope | None] = ContextVar("prompt_cache_affinity", default=None)
_candidate: ContextVar[str | None] = ContextVar("prompt_cache_candidate", default=None)


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _warn(name):
    if name not in _warned:
        _warned.add(name)
        logger.warning("Invalid %s; prompt cache affinity disabled", name)


def settings() -> tuple[bool, int]:
    flag = os.environ.get("PROMPT_CACHE_AFFINITY_ENABLED", "").strip().lower()
    if flag in {"", "false", "0", "off", "no"}:
        return False, 900
    if flag not in {"true", "1", "on", "yes"}:
        _warn("PROMPT_CACHE_AFFINITY_ENABLED")
        return False, 900
    raw = os.environ.get("PROMPT_CACHE_AFFINITY_TTL_SECONDS", "").strip()
    if raw and (not raw.isascii() or not raw.isdigit() or len(raw) > 5 or not 1 <= int(raw) <= 86400):
        _warn("PROMPT_CACHE_AFFINITY_TTL_SECONDS")
        return False, 900
    return True, int(raw or "900")


@dataclass(frozen=True)
class Binding:
    revision: str
    model: str
    credential: str
    expires: float
    cache_read_tokens: int | None = None
    estimated_cache_read_cost_microusd: float | None = None
    estimated_rebuild_cost_microusd: float | None = None


def cache_cost_evidence(model, usage):
    """Measured cache-read counts; catalogue-derived costs remain estimates."""
    from services.prompt_cache_cost import CacheObservation, price_buckets
    if not isinstance(usage, CacheObservation) or usage.basis != "provider":
        return None, None, None
    if usage.cache_read is None:
        return None, None, None
    actual = price_buckets(model, usage)["cache_read_input_cost_microusd"]
    rebuild = replace(usage, input_tokens=usage.cache_read, output_tokens=0,
                      raw_input=usage.cache_read, cache_read=0, cache_write=0, source="openai")
    estimate = price_buckets(model, rebuild)["ordinary_input_cost_microusd"]
    return usage.cache_read, actual, estimate


class PromptCacheAffinity:
    """Process-local, hash-only LRU. Concurrent finalization is serialized."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic, max_entries=MAX_ENTRIES):
        self.clock = clock
        self.max_entries = min(MAX_ENTRIES, max(1, max_entries))
        self._entries: OrderedDict[str, Binding] = OrderedDict()
        self._lock = threading.Lock()

    def _purge(self):
        now = self.clock()
        for key, value in tuple(self._entries.items()):
            if value.expires <= now:
                self._entries.pop(key, None)

    def lookup(self, key, revision):
        with self._lock:
            found = self._entries.get(key)
            if found is None:
                return None
            if found.expires <= self.clock() or found.revision != revision:
                self._entries.pop(key, None)
                return None
            self._entries.move_to_end(key)
            return found

    def bind(self, key, revision, model, credential, ttl, evidence=(None, None, None)):
        with self._lock:
            self._purge()
            self._entries[key] = Binding(revision, model, credential, self.clock() + ttl, *evidence)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def evict(self, key, binding):
        with self._lock:
            if self._entries.get(key) == binding:
                self._entries.pop(key, None)

    def entries(self):
        with self._lock:
            self._purge()
            return tuple(self._entries.items())

    def __len__(self):
        return len(self.entries())


store = PromptCacheAffinity()


@dataclass(frozen=True)
class AffinityScope:
    storage: PromptCacheAffinity
    identity: str
    revision: str
    ttl: int

    def binding(self):
        enabled, ttl = settings()
        return self.storage.lookup(self.identity, self.revision) if enabled and ttl == self.ttl else None

    def record(self, model: str, credential: str, outcome: UpstreamOutcome, *, usage=None):
        self.observer(model, credential)(outcome, usage)

    def observer(self, model: str, credential: str):
        # Capture only an opaque credential fingerprint across lazy streaming.
        fingerprint = _digest(credential)
        def observed(outcome, usage=None):
            enabled, ttl = settings()
            if not enabled or ttl != self.ttl:
                return
            if outcome.provider_health == "success" and outcome.credential_health == "accepted":
                self.storage.bind(self.identity, self.revision, model, fingerprint, ttl,
                                  cache_cost_evidence(model, usage))
            else:
                found = self.binding()
                if found is not None and found.model == model and found.credential == fingerprint:
                    self.storage.evict(self.identity, found)
        return observed

    def preferred_key(self, model: str, eligible: list[str]):
        found = self.binding()
        if found is None or found.model != model:
            return None
        for key in eligible:
            if _digest(key) == found.credential:
                return key
        self.storage.evict(self.identity, found)
        return None

    def preferred_model(self, eligible: list[str], tiers: dict):
        found = self.binding()
        if found is None:
            return None
        if found.model not in eligible:
            self.storage.evict(self.identity, found)
            return None
        # Missing tier evidence preserves ordered fallback semantics.
        if not eligible or eligible[0] not in tiers or found.model not in tiers:
            return None
        return found.model if tiers[found.model] == tiers[eligible[0]] else None

    def order_candidates(self, eligible: list[str], tiers: dict) -> list[str]:
        preferred = self.preferred_model(eligible, tiers)
        return [preferred, *(model for model in eligible if model != preferred)] if preferred else list(eligible)


def make_scope(*, principal, session, role, payload, revision, route) -> AffinityScope | None:
    enabled, ttl = settings()
    if not enabled or not principal or not role:
        return None
    prefix = reusable_prefix_digest(payload)
    if prefix is None:
        return None
    try:
        identity = _digest([principal, session, role, route, prefix])
        policy = _digest([revision, ttl])
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return None
    return AffinityScope(store, identity, policy, ttl)


def request_scope(payload, config):
    """Only authenticated, managed automatic text routes create a scope."""
    if not settings()[0] or not has_request_context():
        return None
    if request.path not in {"/v1/chat/completions", "/v1/responses", "/v1/messages"}:
        return None
    model = payload.get("model")
    if not isinstance(model, str) or not model.startswith("auto:"):
        return None
    user = getattr(g, "authenticated_user", None)
    if not isinstance(user, dict) or not (user.get("id") or user.get("username")):
        return None
    principal = [user.get("tenant_id"), user.get("id") or user.get("username")]
    headers = {key.lower(): value for key, value in request.headers.items()}
    metadata = payload.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    session = next((value for value in (headers.get("x-opencode-session"), headers.get("session-id"),
        headers.get("thread-id"), payload.get("session_id"), payload.get("conversation_id"),
        metadata.get("session_id"), metadata.get("conversation_id"), user.get("session_id"))
        if isinstance(value, str) and value.strip()), "prefix")
    role = [user.get("role") or ("admin" if user.get("is_admin") else "user"),
            getattr(g, "prompt_cache_affinity_lane", "default")]
    from services.auto_route_service import AutoRouteService
    route = AutoRouteService.get_route(model)
    if route is None:
        return None
    sync = current_app.extensions.get("config_revision_sync")
    revisions = {name: state["revision"] for name, state in sync.status()["domains"].items()} if sync else None
    revision = [route.candidates, route.updated_at, getattr(g, "gateway_policy_revision", None),
                revisions,
                user.get("scopes"), user.get("allowed_models"), config.get("PROMPT_CACHE_ENABLED"),
                config.get("PROMPT_CACHE_MIN_TOKENS"), config.get("NANOGPT_SUBSCRIPTION_ONLY")]
    return make_scope(principal=principal, session=session, role=role, payload=payload,
                      revision=revision, route=model)


@contextmanager
def activate_scope(scope):
    token = _active.set(scope)
    try:
        yield
    finally:
        _active.reset(token)


@contextmanager
def candidate_scope(model):
    token = _candidate.set(model)
    try:
        yield
    finally:
        _candidate.reset(token)


def current_scope():
    return _active.get()


def affinity_auto_request(dispatch):
    @wraps(dispatch)
    def wrapped(app, auth, metrics, proxy, payload, **kwargs):
        if current_scope() is not None:
            return dispatch(app, auth, metrics, proxy, payload, **kwargs)
        with activate_scope(request_scope(payload, app.config)):
            return dispatch(app, auth, metrics, proxy, payload, **kwargs)
    return wrapped


def affinity_candidate(dispatch):
    @wraps(dispatch)
    def wrapped(app, auth, metrics, proxy, payload, **kwargs):
        with candidate_scope(payload.get("model")):
            return dispatch(app, auth, metrics, proxy, payload, **kwargs)
    return wrapped


def prefer_credential(provider, model, eligible):
    scope = current_scope()
    candidate = _candidate.get()
    if scope is None or candidate is None or candidate.split(":", 1)[0] != provider:
        return None
    return scope.preferred_key(candidate, eligible)
