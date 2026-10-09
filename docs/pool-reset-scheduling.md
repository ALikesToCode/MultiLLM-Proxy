# Reset-aware account pool scheduling

Reset scheduling is disabled by default. It refines account choice inside the
provider pool and priority tier already selected by the gateway. It does not
change provider order, model choice, authorization, request bodies or replay
permission.

```sh
POOL_RESET_SCHEDULING_ENABLED=false
POOL_OBSERVATION_TTL_SECONDS=60
```

To enable local reset scheduling:

```sh
POOL_RESET_SCHEDULING_ENABLED=true
POOL_OBSERVATION_TTL_SECONDS=60
```

An empty flag means disabled. An empty TTL means 60 seconds. The TTL accepts
integers from 5 through 3600 seconds. A malformed setting disables scheduling
and emits one warning per setting per process, without its value.

## Account choice

The scheduler first applies the existing credential and model cooldowns. Fresh
quota windows with zero remaining quota also exclude an account. Among accounts
with fresh usable observations, the earliest relevant reset wins, with the
configured account order breaking ties. Accounts with no fresh usable evidence
retain their existing positions; only positions with fresh evidence reorder.
For example, two observed accounts with resets in 100 and 20 seconds exchange
order, while an unobserved account between them stays in its position.

Account observations apply across models. Model observations apply only to the
same model; an explicitly supplied quota bucket shares observations only within
that bucket. Raw and unified NanoGPT pools have distinct identities. Existing
prompt cache affinity may prefer an account only after this eligibility filter.

Contradictory quota totals, negative or nonfinite values, conflicting absolute
and relative reset timestamps, missing reset/quota pairs, expired windows and
stale observations do not change legacy eligibility or ordering. Remaining quota
can be derived from consistent limit and used values. Multiple relevant windows
are checked independently: any fresh exhausted window excludes the account.
An expired reset stops supplying advice; it does not assert that quota renewed.

When every configured account is cooling or freshly exhausted, selection raises
the existing model cooldown HTTP 429 error before dispatch. Its error body stays
the same. `Retry-After` uses the soonest fresh reset, rounded up and bounded to
1–3600 seconds, also respecting a smaller configured model cooldown maximum.
Without fresh reset evidence it uses the existing cooldown advice. Advice never
authorizes another request or clears a cooldown. The gateway's cooldown error
adapter must be registered to expose `Retry-After` on HTTP responses.

## Observation sources and cost

The scheduler consumes normalized windows only from authorized usage snapshots
already fetched by the gateway and from metadata already supplied with classified
request results. Cached snapshots do not renew observation freshness. NanoGPT's
subscription usage endpoint is excluded as a scheduling source. No observations
come from browser sessions, subscriptions, rewards or check-ins.

`record_pool_usage(provider, credential, windows, observed_at=..., model=...,
quota_bucket=...)` consumes already received normalized windows. Pool result
methods also accept `usage_windows`; a classified quota throttle with existing
`retry_after_seconds` supplies exhausted quota and a relative reset. Callers must
pass trusted response metadata with the actual credential and dispatch scope.
Unscoped metadata is account-wide; no model scope is inferred from an unrelated
request. The scheduler itself performs no network, storage or refresh calls.

With reset scheduling enabled, NanoGPT's existing catalog validation probes
keep their cadence. The scheduler adds no probes of its own; it filters freshly
exhausted keys and orders eligible keys before the existing validation logic
runs. A validated active key stays in use until its existing re-check unless a
fresh observation shows it exhausted. The selection method that does not probe
continues to use local cooldown and quota evidence without claiming validation.

## Retention and bounds

State is process-local and disappears on restart. There is no distributed
account-state guarantee and no persistent table. At most 10,000 account/scope
observations are retained, with at most 32 quota windows per observation.
Expired observations are removed before the oldest received observation is
evicted for capacity. Newer observations supersede older observations for the
same identity and scope; delayed older updates cannot replace fresh evidence.

Only salted HMAC credential identities are stored, never keys or key prefixes.
Neither observations nor requests are logged. Freshness is checked with wall
and monotonic clocks. Future timestamp skew is tolerated up to five seconds,
without extending the TTL; larger skew and backward clock movement invalidate
observations. Reset timestamps are accepted up to one year after observation.
TTL expiration, missing evidence and capacity eviction restore existing account
selection; these observations are scheduling advice, not a quota accounting
authority. They cannot certify provider metering or live reset behavior.
