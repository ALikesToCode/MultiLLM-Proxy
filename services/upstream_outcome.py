"""Independent replay, provider and credential signals for one transport result."""

from dataclasses import dataclass
from typing import Literal

PROVIDER_FAILURE_STATUS_CODES = frozenset({408, 500, 502, 503, 504})
ProviderHealth = Literal["success", "failure", "neutral"]
CredentialHealth = Literal["accepted", "rejected", "throttled", "unknown"]
TransportFailure = Literal["connect", "timeout", "interrupted"]


@dataclass(frozen=True)
class UpstreamOutcome:
    replay_permission: bool
    provider_health: ProviderHealth
    credential_health: CredentialHealth
    reason: str


def classify_upstream_outcome(
    status_code: int | None = None,
    *,
    transport_failure: TransportFailure | None = None,
    cancelled: bool = False,
    replay_permission: bool = False,
) -> UpstreamOutcome:
    """Describe evidence without granting replay or changing credential state.

    The transport supplies replay_permission from its existing policy. Neither a
    health signal nor a response body can grant permission here. Cancellation
    always removes replay permission and takes precedence over other evidence.
    """
    if cancelled:
        return UpstreamOutcome(False, "neutral", "unknown", "cancelled")
    if transport_failure is not None:
        return UpstreamOutcome(
            replay_permission, "failure", "unknown", f"transport_{transport_failure}"
        )
    if status_code is not None and 200 <= status_code < 300:
        return UpstreamOutcome(replay_permission, "success", "accepted", "http_success")
    if status_code in PROVIDER_FAILURE_STATUS_CODES:
        return UpstreamOutcome(
            replay_permission, "failure", "unknown", "http_provider_failure"
        )
    if status_code in (401, 403):
        return UpstreamOutcome(
            replay_permission, "neutral", "rejected", "http_credential_rejected"
        )
    if status_code == 429:
        return UpstreamOutcome(
            replay_permission, "neutral", "throttled", "http_throttled"
        )
    if status_code is not None and 400 <= status_code < 500:
        return UpstreamOutcome(
            replay_permission, "neutral", "unknown", "http_caller_error"
        )
    reason = "http_neutral" if status_code is not None else "unknown"
    return UpstreamOutcome(replay_permission, "neutral", "unknown", reason)
