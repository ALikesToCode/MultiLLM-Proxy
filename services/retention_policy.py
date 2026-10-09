"""Immutable, prospective retention decisions resolved after authentication."""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Mapping

from flask import g, has_request_context, request

HEADER = "X-MultiLLM-Retention"
_MODES = {"inherit", "zero"}
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RetentionPolicy:
    mode: str = "inherit"
    enabled: bool = False
    revision: str = "legacy"

    @property
    def allows_content(self) -> bool:
        return not self.enabled or self.mode != "zero"


@lru_cache(maxsize=2)
def _warn_once(setting: str) -> None:
    logger.warning("Invalid %s; content retention controls disabled", setting)


def _rules(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) and bool(key) and isinstance(mode, str) and mode in _MODES
               for key, mode in value.items())


def resolve_policy(env: Mapping[str, str] | None = None, *, key_id: str = "",
                   route: str = "", header: str = "", key_hash: str = "") -> RetentionPolicy:
    """Tightest of default, authenticated key, exact route and caller opt-out."""
    env = os.environ if env is None else env
    flag = str(env.get("CONTENT_RETENTION_ENABLED", "")).strip().lower()
    if flag in {"", "0", "false", "no", "off"}:
        return RetentionPolicy()
    if flag not in {"1", "true", "yes", "on"}:
        _warn_once("CONTENT_RETENTION_ENABLED")
        return RetentionPolicy()
    raw = env.get("CONTENT_RETENTION_POLICY_JSON", "").strip() or "{}"
    try:
        config = json.loads(raw)
        if (not isinstance(config, dict) or set(config) - {"default", "keys", "routes"}
                or not isinstance(config.get("default", "inherit"), str)
                or config.get("default", "inherit") not in _MODES
                or not _rules(config.get("keys", {})) or not _rules(config.get("routes", {}))):
            raise ValueError("Invalid retention configuration")
    except (ValueError, TypeError):
        _warn_once("CONTENT_RETENTION_POLICY_JSON")
        return RetentionPolicy()
    modes = [config.get("default", "inherit"), config.get("routes", {}).get(route),
             config.get("keys", {}).get(key_id), config.get("keys", {}).get(key_hash),
             str(header).strip().lower()]
    revision = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return RetentionPolicy("zero" if "zero" in modes else "inherit", True, revision)


def request_policy() -> RetentionPolicy:
    """Snapshot once per request; stream callbacks must capture the returned value."""
    if not has_request_context():
        return RetentionPolicy()
    captured = getattr(g, "multillm_content_retention", None)
    if isinstance(captured, RetentionPolicy):
        return captured
    user = getattr(g, "authenticated_user", None) or {}
    from route_helpers import request_api_key
    key = request_api_key() if user else ""
    key_hash = hashlib.sha256(key.encode()).hexdigest() if key else ""
    policy = resolve_policy(key_id=str(user.get("id") or user.get("username") or ""),
                            key_hash=key_hash, route=request.path, header=request.headers.get(HEADER, ""))
    g.multillm_content_retention = policy
    if policy.enabled:
        g.multillm_retention_policy = {"mode": policy.mode, "revision": policy.revision}
    return policy


def init_retention_policy(app) -> None:
    """Coordinator hook: call after authentication and before managed dispatch."""
    @app.before_request
    def capture_retention():
        if getattr(g, "authenticated_user", None):
            request_policy()
