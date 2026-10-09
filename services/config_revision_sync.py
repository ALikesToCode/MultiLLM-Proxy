"""Bounded revision polling on the existing control-state background scheduler."""
from __future__ import annotations

import logging
import math
import os
import random
import re
import threading
import time
from dataclasses import dataclass
from collections.abc import Callable, Mapping
from functools import partial

from services import auto_route_d1, control_state_d1, key_controls, model_override_d1
from services.auth_service import AuthService

logger = logging.getLogger(__name__)
_warned: set[str] = set()
_active: RevisionSync | None = None
_active_lock = threading.Lock()
SECURITY_DOMAINS = ("model_overrides", "key_controls", "model_grants")
ORDINARY_DOMAINS = ("auto_routes", "provider_catalog")


@dataclass(frozen=True)
class SyncSettings:
    enabled: bool = False
    ttl: float = 30
    security_ttl: float = 5


def _invalid(name):
    if name not in _warned:
        _warned.add(name)
        logger.warning("Invalid %s; configuration revision sync disabled", name)


def load_settings(env: Mapping[str, str] | None = None) -> SyncSettings:
    env = os.environ if env is None else env
    flag = env.get("CONFIG_REVISION_SYNC_ENABLED", "").strip().lower()
    if flag not in {"", "0", "false", "no", "off", "1", "true", "yes", "on"}:
        _invalid("CONFIG_REVISION_SYNC_ENABLED")
        return SyncSettings()
    if flag not in {"1", "true", "yes", "on"}:
        return SyncSettings()
    values = []
    for name, default, maximum in (("CONFIG_SYNC_TTL_SECONDS", 30, 3600), ("CONFIG_SECURITY_TTL_SECONDS", 5, 5)):
        text = env.get(name, "").strip()
        if not text:
            values.append(default)
            continue
        if not re.fullmatch(r"(?:\d+(?:\.\d*)?|\.\d+)", text):
            _invalid(name)
            return SyncSettings()
        value = float(text)
        if not math.isfinite(value) or not 1 <= value <= maximum:
            _invalid(name)
            return SyncSettings()
        values.append(value)
    return SyncSettings(True, *values)


@dataclass
class DomainState:
    refresh: Callable[[int], None]
    security: bool
    revision: int | None = None
    observed: int | None = None
    checked: float | None = None
    due: float = 0


class RevisionSync:
    """Refresh a loaded copy only on newer revisions; never renew failed security reads."""

    def __init__(self, settings: SyncSettings, *, fetch=None, clock=time.monotonic, jitter=random.random):
        self.settings = settings
        self.fetch = fetch or fetch_revisions
        self.clock, self.jitter = clock, jitter
        self._domains: dict[str, DomainState] = {}
        self._lock = threading.RLock()
        self._poll_lock = threading.Lock()
        self.routes: dict = {}

    def register(self, domain: str, refresh: Callable[[int], None], *, security=False):
        with self._lock:
            self._domains[domain] = DomainState(refresh, security)

    def _ttl(self, state):
        return self.settings.security_ttl if state.security else self.settings.ttl

    @staticmethod
    def _validate(revisions, domains):
        if not isinstance(revisions, dict) or set(revisions) != set(domains) or any(
            type(value) is not int or not 0 <= value <= 9007199254740991 for value in revisions.values()
        ):
            raise ValueError("Invalid revision metadata")

    def tick(self, final=False):
        if not self.settings.enabled or final or not self._poll_lock.acquire(blocking=False):
            return
        try:
            for security in (True, False):
                self._poll_group(security)
        finally:
            self._poll_lock.release()

    def _poll_group(self, security):
        started = self.clock()
        with self._lock:
            due = {name: state for name, state in self._domains.items() if state.security == security and started >= state.due}
            for state in due.values():
                # Negative jitter keeps freshness within TTL and a failed poll cannot hot-loop.
                state.due = started + self._ttl(state) * (0.8 + 0.2 * min(1, max(0, self.jitter())))
        if not due:
            return
        try:
            revisions = self.fetch(list(due))
            self._validate(revisions, due)
        except Exception:
            logger.warning("Configuration revision metadata unavailable")
            return
        changed = {}
        for name, state in due.items():
            revision = revisions[name]
            with self._lock:
                if state.observed is not None and revision < state.observed:
                    state.checked = None
                    continue
                state.observed = revision
                if state.revision == revision:
                    state.checked = started
                    continue
                # Observing a new security revision immediately invalidates the older copy.
                state.checked = None
            try:
                state.refresh(revision)
                changed[name] = revision
            except Exception:
                logger.warning("Configuration domain refresh unavailable domain=%s", name)
        if not changed:
            return
        try:
            confirmed = self.fetch(list(changed))
            self._validate(confirmed, changed)
        except Exception:
            logger.warning("Configuration revision confirmation unavailable")
            return
        with self._lock:
            for name, revision in changed.items():
                due[name].observed = max(due[name].observed or 0, confirmed[name])
                if confirmed[name] == revision:
                    due[name].revision, due[name].checked = revision, started
                # Concurrent writes are retried at the next bounded poll, never in a loop.

    def security_ready(self):
        if not self.settings.enabled:
            return True
        now = self.clock()
        with self._lock:
            security = [state for state in self._domains.values() if state.security]
            return bool(security) and all(state.checked is not None and now - state.checked <= self.settings.security_ttl for state in security)

    def status(self):
        now = self.clock()
        with self._lock:
            return {"enabled": self.settings.enabled, "domains": {name: {
                "revision": state.revision,
                "age_seconds": None if state.checked is None else max(0, now - state.checked),
                "stale": state.checked is None or now - state.checked > self._ttl(state),
                "security": state.security,
                "next_poll_seconds": max(0, state.due - now),
            } for name, state in self._domains.items()}}


def fetch_revisions(domains):
    if not control_state_d1.using_d1():
        raise ValueError("Revision authority requires D1")
    response = control_state_d1.call("model_overrides", "revisions", domains=domains)
    if not isinstance(response, dict) or set(response) != {"version", "revisions"} or response["version"] != 1:
        raise ValueError("Invalid revision metadata envelope")
    return response["revisions"]


def _refresh_routes(sync, revision):
    routes = auto_route_d1._routes(control_state_d1.call("auto_routes", "list"))
    with sync._lock:
        sync.routes = routes


def _refresh_models(revision):
    overrides = model_override_d1._overrides(control_state_d1.call("model_overrides", "list"))
    with model_override_d1._lock:
        model_override_d1._cache.update(overrides=overrides, expires=float("inf"))


def missing_security_refresh(revision):
    raise ValueError("Security revision collaborator is not configured")


def supported_settings(settings):
    """Revision authority and accounts must both live in Container D1 storage."""
    if settings.enabled and (not control_state_d1.using_d1()
            or os.environ.get("AUTH_STORAGE_BACKEND", "").strip().lower() != "d1"):
        name = "CONFIG_REVISION_SYNC_RUNTIME"
        if name not in _warned:
            _warned.add(name)
            logger.warning("Configuration revision sync requires Container D1 control and account storage; disabled")
        return SyncSettings()
    return settings


def configure_sync(settings, *, security_refreshers=None, catalog_refresh=None):
    """Security authorities must install a verified copy or raise, never a fallback copy."""
    global _active
    settings = supported_settings(settings)
    if not settings.enabled:
        return RevisionSync(settings)
    with _active_lock:
        if _active is None:
            _active = RevisionSync(settings)
            _active.register("auto_routes", partial(_refresh_routes, _active))
            if catalog_refresh is not None:
                _active.register("provider_catalog", catalog_refresh)
            callbacks = {"model_overrides": _refresh_models,
                         "key_controls": partial(key_controls.refresh_security_copy, AuthService),
                         "model_grants": partial(key_controls.refresh_security_copy, AuthService),
                         **(security_refreshers or {})}
            for name in SECURITY_DOMAINS:
                _active.register(name, callbacks.get(name) or missing_security_refresh, security=True)
            control_state_d1.register(_active.tick)
        sync = _active
    control_state_d1.ensure_running()
    return sync


def route_copy():
    if not load_settings().enabled or _active is None or not _active.settings.enabled:
        return None
    with _active._lock:
        return dict(_active.routes)


def request_poll(app):
    """Reads wake the existing scheduler; they never poll storage on a request thread."""
    sync = app.extensions.get("config_revision_sync")
    if sync is not None and sync.settings.enabled:
        control_state_d1.wake()
