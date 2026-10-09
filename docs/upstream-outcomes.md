# Upstream outcomes

Provider circuit recovery uses independent provider and credential signals. The
change applies to the common Flask transport, including requests forwarded to
its Container. It requires no feature flag, new dependencies or schema changes.
Native Worker adapters retain their own health policy.

## HTTP status matrix

| Result | Provider health | Credential health | Circuit effect |
| --- | --- | --- | --- |
| 200–299 | success | accepted | Counts toward recovery at the existing threshold |
| 401, 403 | neutral | rejected | Releases a half-open probe without recovery or outage penalty |
| 429 | neutral | throttled | Releases a half-open probe and increments rate-limit events |
| 408, 500, 502, 503, 504 | failure | unknown | Retains the existing outage penalty and reopening thresholds |
| Other 4xx, including 400, 402, 404, 422 | neutral | unknown | Releases a half-open probe without recovery or outage penalty |
| All other statuses | neutral | unknown | Releases a half-open probe without recovery or outage penalty |

A neutral result preserves consecutive failures and accumulated recovery
successes. It releases one occupied half-open slot, never decrements below zero,
and cannot close a degraded, open or half-open circuit. Valid 2xx results retain
the existing recovery behavior, including protection against a stale success
clearing a circuit reopened by another probe.

## Replay and transport evidence

`services/upstream_outcome.py` provides the frozen `UpstreamOutcome` value and
`classify_upstream_outcome`. The classifier uses only the standard library and
returns `replay_permission`, `provider_health`, `credential_health` and `reason`.
It does not inspect response bodies, credentials or pool state.

Replay permission defaults to false. A caller may supply a permission already
computed by the existing transport policy; classification itself grants no
retry. Circuit bookkeeping has no replay context and uses the false default.
Neither neutral credential rejection nor an outage signal changes request
methods, retry counts, idempotency handling or stream commitment rules.

The transport continues to distinguish a connection timeout before dispatch
from a read timeout or interrupted connection whose request may have been sent.
Terminal managed transport errors keep their existing provider-failure penalty
and HTTP error response. Their outcome reason records `transport_connect`,
`transport_timeout` or `transport_interrupted`; all have unknown credential
health. The existing exception retry helper permits a connection timeout retry,
but an ambiguous failure on a POST remains non-replayable even when an
Idempotency-Key is present. Existing safe-method/no-body exceptions and status
retry policy are unchanged.

Explicit cancellation evidence (`cancelled=True`) takes precedence over status
or transport evidence: it is neutral with unknown credential health and no
replay permission. Callers can pass this outcome to
`ResilienceService.record_result(provider, status, outcome=outcome, now=...)` to
release a probe. This change does not add cancellation hooks or treat an
interrupted connection as proven cancellation. Existing calls using only the
provider, status and optional `now` keyword continue to work.

Raw/passthrough transport keeps its circuit bypass and single upstream forward.
It does not classify circuit results or read, normalize or retry response bytes
through this module. Managed normalization and all HTTP envelopes stay as they
were before this bookkeeping change.

Credential signals are descriptive. This module does not delete, rotate, cool
down or otherwise mutate keys. Existing credential-pool penalties remain in
place; model-specific credential health integration is outside this change.
No request content, provider body or secret is retained by the outcome value.

## Deployment

There is no configuration, package script or Container environment entry.
