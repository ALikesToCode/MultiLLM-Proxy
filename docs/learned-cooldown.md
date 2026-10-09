# Learned provider cooldowns

Cooldown tuning uses natural throttle and recovery outcomes already recorded by
the credential pools. It sends no probes or extra provider requests. It adjusts
only a cooldown duration; route order, credential preference and permission to
replay a request remain controlled by their existing policies.

## Configuration

The default is disabled:

```sh
LEARNED_COOLDOWN_MODE=off
LEARNED_COOLDOWN_POLICY_JSON='{}'
```

Empty values use these defaults. A malformed mode or policy disables tuning and
logs one warning without the supplied value. Modes are `off`, `shadow` and
`apply`. Policies contain only a `buckets` array, with at most 128 entries and
32 KiB of JSON. Each entry requires exactly `provider`, `model` and
`quota_bucket`. Provider must be a nonempty string; model and quota bucket are
nonempty strings or `null`, and at least one must be nonnull. Names match
exactly, including null values. Wildcards, duplicate fields, duplicate scopes,
control characters and unknown fields are rejected.

To observe a specific model without changing its existing cooldown:

```sh
LEARNED_COOLDOWN_MODE=shadow
LEARNED_COOLDOWN_POLICY_JSON='{"buckets":[{"provider":"ce-gpt-pro","model":"gpt-5","quota_bucket":null}]}'
```

Shadow logs the suggested seconds, opaque bucket digest, confidence and step
count. It preserves existing cooldowns and selection. Change the mode to
`apply` to use a suggested duration after sufficient consistent evidence.
For a named quota bucket, specify its exact name and the model recorded by the
transport. A quota-only observation uses `model:null`. A configured name learns
nothing until a pool receives natural outcomes with that exact scope.

`MODEL_COOLDOWN_ENABLED` still controls the existing model-scoped admission
policy. Tuning does not enable it. With model cooldowns disabled, the pool keeps
its legacy credential-wide rest semantics while learning separate scope records.

## Evidence and bounds

The interval starts at 1–3,600 seconds. A later natural throttle in the same
credential/model/quota bucket raises its lower bound from the failed wait.
A genuine successful request after a throttle lowers its upper bound from the
elapsed wait. Success without a preceding throttle provides no recovery sample.
Authentication rejection, caller errors, cancellation, transport errors and
catalog validation probes provide no learning evidence.

Three consistent directional observations allow a midpoint trial. Each state
allows at most 12 trial steps. Contradictory observations or nonincreasing
timestamps widen the interval and remove confidence. Apply uses the existing
cooldown until confidence returns. The existing model cooldown cap also bounds
an applied trial. Trusted Retry-After or reset seconds supplied
by the transport are a hard minimum, even when longer than 3,600 seconds. Such
hints can prevent any shortening. Invalid or nonfinite hints are ignored. No
header is parsed or rewritten by the learner.

Each credential, provider, model and quota bucket has separate evidence. Model
and quota names are never stored. Credential-keyed HMAC digests provide stable
opaque identities across processes; credentials and prefixes are never stored
in learned state. Rotating a credential creates a new identity.

## Storage, errors and retention

Standalone Flask uses process-local state, bounded to 1,024 entries. It resets
on process restart and is not a distributed quota authority. State expires
seven days after creation; observations do not extend its lifetime.

With `INTELLIGENCE_STORAGE_BACKEND=d1`, learned state uses the private
`/v1/state/learned-cooldown` storage domain, backed by the additive
`0031_learned_cooldown.sql` migration. Its fixed operations are `get` and `put`;
puts use revision comparison and a transactional capacity check. Storage is
bounded to 1,024 rows. Reads ignore expired state; writes reclaim expired rows.
Physical deletion therefore depends on subsequent writes rather than a timer.

A missing table or unavailable D1 store returns a sanitized JSON 503 from the
private storage operation. The pool falls back to its existing cooldown with
one warning and continues serving traffic. A stale revision, invalid stored
state or full capacity also prevents applying a suggestion. No public route or
new response header is introduced. Default-off mode performs no learned-state
storage operations or reports.

Natural traffic can be sparse, concurrent or affected by changing provider
limits. The inferred interval is a suggestion, not proof of a provider's quota
or successful recovery. Shadow observation and D1 writes add storage work;
they add no provider usage, usage refreshes or paid generation calls. Existing
transport accounting and retry safety remain authoritative.
