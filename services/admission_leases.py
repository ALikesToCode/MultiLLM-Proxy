"""Private shared concurrency leases; local bookkeeping is never the authority."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
import time
import weakref
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests
from error_handlers import APIError

logger = logging.getLogger(__name__)
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_GROUP = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_LEASE = re.compile(r"[0-9a-f]{32}\Z")
LEASE_MS = 30_000
RENEW_MS = 10_000
MAX_OUTSTANDING = 10_000
_warned = False
_scheduler_lock = threading.Lock()
_clients: weakref.WeakSet = weakref.WeakSet()
_scheduler = None


def principal_hash(username: str) -> str:
    """Shared authenticated account identity; never hash an unverified caller header."""
    return hashlib.sha256(f"multillm-admission:v1:{username.strip()}".encode("utf-8")).hexdigest()


def model_group(model, provider=None) -> str:
    candidate = f"{provider}:{model}" if provider and isinstance(model, str) else model
    return candidate if isinstance(candidate, str) and _GROUP.fullmatch(candidate) else (provider or "default")


class AdmissionError(APIError):
    def __init__(self, code="admission_unavailable", status=503, retry_after=None):
        super().__init__("Concurrency admission failed.", status_code=status)
        self.code, self.status, self.retry_after = code, status, retry_after


@dataclass(frozen=True)
class AdmissionSettings:
    enabled: bool = False
    principal: int = 0
    groups: dict | None = None

    def limited(self, group=None):
        groups = self.groups or {}
        return bool(self.principal or (groups.get(group, 0) if group is not None else any(groups.values())))


def admission_settings(env=None):
    global _warned
    env = os.environ if env is None else env
    flag = str(env.get("ADMISSION_ENABLED", "")).strip().lower()
    if flag in {"", "false", "0"}:
        return AdmissionSettings()
    try:
        if flag not in {"true", "1"}:
            raise ValueError("flag")
        limits = json.loads(str(env.get("ADMISSION_LIMITS_JSON", "")).strip() or "{}")
        def valid_limit(value):
            return type(value) is int and 0 <= value <= MAX_OUTSTANDING
        if not isinstance(limits, dict) or set(limits) - {"principal", "model_groups"}:
            raise ValueError("limits")
        if "principal" in limits and not valid_limit(limits["principal"]):
            raise ValueError("principal")
        groups = limits.get("model_groups", {})
        if (not isinstance(groups, dict) or len(groups) > 256
                or any(not _GROUP.fullmatch(key) or not valid_limit(value) for key, value in groups.items())):
            raise ValueError("groups")
        return AdmissionSettings(True, limits.get("principal", 0), groups)
    except (ValueError, TypeError):
        if not _warned:
            _warned = True
            logger.warning("Invalid admission configuration; admission is disabled.")
        return AdmissionSettings()


@dataclass(frozen=True)
class AdmissionIdentity:
    """Opaque authenticated key identity and authorized group, supplied by the registrar."""
    principal_hash: str
    model_group: str
    request_id: str
    deadline_ms: int

    def valid(self):
        return (isinstance(self.principal_hash, str) and _HASH.fullmatch(self.principal_hash)
                and isinstance(self.model_group, str) and _GROUP.fullmatch(self.model_group)
                and isinstance(self.request_id, str) and _ID.fullmatch(self.request_id)
                and type(self.deadline_ms) is int and self.deadline_ms > 0)

    def payload(self, operation, lease_id=None):
        result = {"version": 1, "operation": operation, "principal_hash": self.principal_hash,
                  "model_group": self.model_group, "request_id": self.request_id, "deadline_ms": self.deadline_ms}
        if lease_id is not None:
            result["lease_id"] = lease_id
        return result


def _authority_url(env):
    configured = str(env.get("ADMISSION_AUTHORITY_URL", "")).strip()
    if not configured and env.get("INTELLIGENCE_STORAGE_BACKEND", "").strip() == "d1":
        configured = "http://intelligence.internal/v1/admission"
    parsed = urlsplit(configured)
    host = parsed.hostname or ""
    try:
        private = ipaddress.ip_address(host).is_private
    except ValueError:
        private = host == "localhost" or host.endswith(".internal")
    if (parsed.scheme not in {"http", "https"} or not private or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path != "/v1/admission"):
        raise AdmissionError()
    return configured


def _private_call(env, payload):
    """Fixed private operation, one submission, no redirects, proxies or response content logs."""
    url = _authority_url(env)
    with requests.Session() as session:
        session.trust_env = False
        with session.post(url, json=payload, headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                          timeout=(2, 3), allow_redirects=False, stream=True) as response:
            if (response.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json"
                    or response.headers.get("Content-Encoding", "identity").lower() != "identity"):
                raise AdmissionError()
            body = bytearray()
            deadline = time.monotonic() + 5
            for chunk in response.iter_content(chunk_size=4096):
                if len(body) + len(chunk) > 4096 or time.monotonic() >= deadline:
                    raise AdmissionError()
                body.extend(chunk)
            result = json.loads(body)
            if not isinstance(result, dict) or type(result.get("version")) is not int or result["version"] != 1:
                raise AdmissionError()
            if response.status_code == 429:
                retry = response.headers.get("Retry-After", "")
                if not retry.isascii() or not retry.isdecimal() or not 1 <= int(retry) <= 86400:
                    raise AdmissionError()
                raise AdmissionError("admission_denied", 429, int(retry))
            if response.status_code != 200 or "error" in result:
                raise AdmissionError()
            return result


def _renew_loop():
    while True:
        time.sleep(1)
        with _scheduler_lock:
            clients = list(_clients)
        for client in clients:
            client.renew_due()


def _register_scheduler(client):
    global _scheduler
    with _scheduler_lock:
        _clients.add(client)
        if _scheduler is None or not _scheduler.is_alive():
            _scheduler = threading.Thread(target=_renew_loop, daemon=True, name="admission-renewal")
            _scheduler.start()


class AdmissionClient:
    def __init__(self, env=None, *, call=None, clock=None, background=True):
        self.env = os.environ if env is None else env
        self.call = call or (lambda payload: _private_call(self.env, payload))
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.background = background
        self._leases: set[AdmissionLease] = set()
        self._lock = threading.Lock()

    def acquire(self, identity, *, on_lost=None):
        settings = admission_settings(self.env)
        if not settings.enabled or not settings.limited():
            return None
        if not isinstance(identity, AdmissionIdentity) or not identity.valid():
            raise AdmissionError("admission_identity_invalid", 403)
        if not settings.limited(identity.model_group):
            return None
        if identity.deadline_ms <= self.clock() or identity.deadline_ms > self.clock() + 86_400_000:
            raise AdmissionError("admission_deadline_invalid", 403)
        # This bound protects local renewal bookkeeping; all admission decisions stay remote.
        with self._lock:
            if len(self._leases) >= MAX_OUTSTANDING:
                raise AdmissionError()
        result = self.submit(identity.payload("acquire"))
        value = result.get("lease")
        self.validate(value, identity)
        lease = AdmissionLease(self, identity, value, on_lost)
        with self._lock:
            self._leases.add(lease)
        if self.background:
            _register_scheduler(self)
        return lease

    def submit(self, payload):
        try:
            result = self.call(payload)
            if not isinstance(result, dict) or type(result.get("version")) is not int or result["version"] != 1 or "error" in result:
                raise AdmissionError()
            return result
        except AdmissionError:
            raise
        except Exception:
            raise AdmissionError() from None

    def validate(self, value, identity, lease_id=None):
        if (not isinstance(value, dict) or not isinstance(value.get("lease_id"), str)
                or not _LEASE.fullmatch(value["lease_id"]) or type(value.get("expires_at")) is not int
                or not self.clock() < value["expires_at"] <= min(self.clock() + LEASE_MS, identity.deadline_ms)
                or (lease_id is not None and value["lease_id"] != lease_id)):
            raise AdmissionError()

    def forget(self, lease):
        with self._lock:
            self._leases.discard(lease)

    def renew_due(self):
        with self._lock:
            leases = list(self._leases)
        for lease in leases:
            lease.renew_due()


class AdmissionLease:
    def __init__(self, client, identity, value, on_lost):
        self.client, self.identity = client, identity
        self.lease_id, self.expires_at = value["lease_id"], value["expires_at"]
        self.next_renewal = client.clock() + RENEW_MS
        self.on_lost = on_lost
        self.closed = False
        self.failure = None
        self._lock = threading.RLock()

    def check(self):
        with self._lock:
            if self.failure:
                raise self.failure
            if self.closed or self.client.clock() >= min(self.expires_at, self.identity.deadline_ms):
                raise AdmissionError()

    def renew_due(self):
        with self._lock:
            if self.closed:
                return
            now = self.client.clock()
            try:
                self.check()
                if now < self.next_renewal:
                    return
                result = self.client.submit(self.identity.payload("renew", self.lease_id))
                value = result.get("lease")
                self.client.validate(value, self.identity, self.lease_id)
                self.expires_at = value["expires_at"]
                self.next_renewal = self.client.clock() + RENEW_MS
                return
            except AdmissionError as error:
                self.failure = error
        # Transport cancellation can wait for readers that call check(); never hold their lock.
        self.release()
        try:
            if self.on_lost:
                self.on_lost(self.failure)
        except Exception:
            logger.warning("Admission cancellation callback failed.")

    def release(self):
        with self._lock:
            if self.closed:
                return
            self.closed = True
            self.client.forget(self)
            try:
                self.client.submit(self.identity.payload("release", self.lease_id))
            except AdmissionError:
                # A lost release response is not replayed; shared expiry is the recovery path.
                logger.warning("Admission release was not confirmed; lease will expire.")
