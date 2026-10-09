"""Explicit immutable authority boundaries; registration grants no permissions."""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal, Mapping, Protocol

logger = logging.getLogger(__name__)
MAX_INTEGER = 9007199254740991


def _opaque(value: object) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_:.\-]{1,128}", value):
        raise ValueError("Invalid opaque identifier")


def _integer(value: object) -> None:
    if type(value) is not int or not 0 <= value < MAX_INTEGER:
        raise ValueError("Invalid bounded integer")


@dataclass(frozen=True)
class TenantContext:
    principal_id: str
    org_id: str | None = None
    team_id: str | None = None
    grants_revision: int = 0

    def __post_init__(self) -> None:
        _opaque(self.principal_id)
        _integer(self.grants_revision)
        for value in (self.org_id, self.team_id):
            if value is not None:
                _opaque(value)
        if self.team_id is not None and self.org_id is None:
            raise ValueError("Team requires organisation scope")


@dataclass(frozen=True)
class IdentityAssertion:
    issuer_id: str
    subject_id: str
    audience_id: str
    request_id: str
    nonce_id: str
    expires_at: int
    verified: bool

    def __post_init__(self) -> None:
        for value in (self.issuer_id, self.subject_id, self.audience_id, self.request_id, self.nonce_id):
            _opaque(value)
        _integer(self.expires_at)
        if self.verified is not True or self.expires_at == 0:
            raise ValueError("Verified identity assertion required")


@dataclass(frozen=True)
class AuthorityOperation:
    context: TenantContext
    scoped_id: str
    revision: int
    operation_id: str
    amount: int = 0

    def __post_init__(self) -> None:
        if type(self.context) is not TenantContext:
            raise TypeError("TenantContext required")
        _opaque(self.scoped_id)
        _opaque(self.operation_id)
        _integer(self.revision)
        _integer(self.amount)


@dataclass(frozen=True)
class AuthorityResult:
    context: TenantContext
    scoped_id: str
    revision: int
    operation_id: str
    allowed: bool

    def __post_init__(self) -> None:
        if type(self.context) is not TenantContext:
            raise TypeError("TenantContext required")
        _opaque(self.scoped_id)
        _opaque(self.operation_id)
        # Results may include the successor of the largest accepted input revision.
        if type(self.revision) is not int or not 0 <= self.revision <= MAX_INTEGER:
            raise ValueError("Invalid revision")
        if type(self.allowed) is not bool:
            raise TypeError("Boolean decision required")


@dataclass(frozen=True)
class PaymentEvent:
    context: TenantContext
    scoped_id: str
    revision: int
    idempotency_id: str
    processor_id: str
    event_id: str
    kind: Literal["credit", "refund", "dispute"]
    currency: str
    amount: int
    verified: bool

    def __post_init__(self) -> None:
        AuthorityOperation(self.context, self.scoped_id, self.revision, self.idempotency_id, self.amount)
        _opaque(self.processor_id)
        _opaque(self.event_id)
        if (self.verified is not True or self.kind not in {"credit", "refund", "dispute"}
                or not isinstance(self.currency, str) or not re.fullmatch(r"[A-Z]{3}", self.currency)):
            raise ValueError("Verified payment event required")


class TenantAuthority(Protocol):
    def __call__(self, operation: AuthorityOperation) -> TenantContext: ...


class IdentityAuthority(Protocol):
    def __call__(self, assertion: IdentityAssertion, operation: AuthorityOperation) -> TenantContext: ...


class QuotaAuthority(Protocol):
    def reserve(self, operation: AuthorityOperation) -> AuthorityResult: ...
    def commit(self, operation: AuthorityOperation) -> AuthorityResult: ...
    def reconcile(self, operation: AuthorityOperation) -> AuthorityResult: ...


class CreditAuthority(QuotaAuthority, Protocol):
    """Integer units and atomic revision semantics are defined by the registered ledger."""


class PaymentCallback(Protocol):
    def __call__(self, event: PaymentEvent) -> AuthorityResult: ...


class AuthorityDenied(Exception):
    """A missing authority or unbound decision cannot grant access."""


def legacy_tenant(operation: AuthorityOperation) -> TenantContext:
    _operation(operation)
    if operation.context.org_id is not None or operation.context.team_id is not None:
        raise AuthorityDenied("tenant_scope_denied")
    return operation.context


@dataclass(frozen=True)
class EnterpriseAdapters:
    tenant: TenantAuthority | None = legacy_tenant
    identity: IdentityAuthority | None = None
    quota: QuotaAuthority | None = None
    credit: CreditAuthority | None = None
    payment: PaymentCallback | None = None


def register_enterprise_adapters(*, tenant: TenantAuthority | None = legacy_tenant,
                                 identity: IdentityAuthority | None = None,
                                 quota: QuotaAuthority | None = None,
                                 credit: CreditAuthority | None = None,
                                 payment: PaymentCallback | None = None) -> EnterpriseAdapters:
    """Return fixed collaborators without importing plugins or calling authorities."""
    for callback in (tenant, identity, payment):
        if callback is not None and not callable(callback):
            raise TypeError("Explicit authority function required")
    for authority in (quota, credit):
        if authority is not None and not all(callable(getattr(authority, name, None))
                                             for name in ("reserve", "commit", "reconcile")):
            raise TypeError("Complete reserve/commit/reconcile authority required")
    return EnterpriseAdapters(tenant, identity, quota, credit, payment)


def _operation(operation: AuthorityOperation) -> None:
    if type(operation) is not AuthorityOperation:
        raise TypeError("AuthorityOperation required")


def _context(result: object, operation: AuthorityOperation) -> TenantContext:
    if type(result) is not TenantContext or result != operation.context:
        raise AuthorityDenied("authority_scope_mismatch")
    return result


def resolve_tenant(adapters: EnterpriseAdapters, operation: AuthorityOperation) -> TenantContext:
    _operation(operation)
    if adapters.tenant is None:
        raise AuthorityDenied("authority_unavailable")
    return _context(adapters.tenant(operation), operation)


def resolve_identity(adapters: EnterpriseAdapters, assertion: IdentityAssertion,
                     operation: AuthorityOperation) -> TenantContext:
    _operation(operation)
    if type(assertion) is not IdentityAssertion or assertion.verified is not True:
        raise TypeError("Verified IdentityAssertion required")
    if adapters.identity is None:
        raise AuthorityDenied("authority_unavailable")
    return _context(adapters.identity(assertion, operation), operation)


def _result(result: object, operation: AuthorityOperation) -> AuthorityResult:
    if (type(result) is not AuthorityResult or not result.allowed
            or result.context != operation.context or result.scoped_id != operation.scoped_id
            or result.operation_id != operation.operation_id or result.revision != operation.revision + 1):
        raise AuthorityDenied("authority_decision_denied")
    return result


def call_authority(adapters: EnterpriseAdapters, authority: Literal["quota", "credit"],
                   action: Literal["reserve", "commit", "reconcile"],
                   operation: AuthorityOperation) -> AuthorityResult:
    _operation(operation)
    if authority not in {"quota", "credit"} or action not in {"reserve", "commit", "reconcile"}:
        raise ValueError("Unknown authority operation")
    target = adapters.quota if authority == "quota" else adapters.credit
    if target is None:
        raise AuthorityDenied("authority_unavailable")
    callback = target.reserve if action == "reserve" else target.commit if action == "commit" else target.reconcile
    return _result(callback(operation), operation)


def deliver_payment(adapters: EnterpriseAdapters, event: PaymentEvent) -> AuthorityResult:
    if type(event) is not PaymentEvent or event.verified is not True:
        raise TypeError("Verified PaymentEvent required")
    if adapters.payment is None:
        raise AuthorityDenied("authority_unavailable")
    operation = AuthorityOperation(event.context, event.scoped_id, event.revision, event.idempotency_id, event.amount)
    return _result(adapters.payment(event), operation)


@lru_cache(maxsize=1)
def _warn_once() -> None:
    logger.warning("Invalid ENTERPRISE_PREVIEW_ENABLED; enterprise preview disabled")


def preview_enabled(env: Mapping[str, str] | None = None) -> bool:
    raw = (os.environ if env is None else env).get("ENTERPRISE_PREVIEW_ENABLED", "")
    flag = raw.strip().lower() if isinstance(raw, str) else "invalid"
    if flag in {"", "0", "false", "no", "off"}:
        return False
    if flag in {"1", "true", "yes", "on"}:
        return True
    _warn_once()
    return False


def preview_descriptor(adapters: EnterpriseAdapters) -> dict:
    return {"version": 1, "dry_run": True, "activation": False,
            "contracts": ["TenantContext", "IdentityAssertion", "QuotaAuthority", "CreditAuthority", "PaymentEvent"],
            "authorities": {name: getattr(adapters, name) is not None
                            for name in ("tenant", "identity", "quota", "credit", "payment")},
            "operations": ["reserve", "commit", "reconcile"], "missing_authority": "denied"}
