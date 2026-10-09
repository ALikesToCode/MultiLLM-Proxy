# Model-scoped credential cooldown

`MODEL_COOLDOWN_ENABLED` defaults to `false`. Disabled pools keep their existing
selection, cooldown, validation and response behavior, including the legacy
Codex Everywhere fallback to the first key when every key is resting.

With the flag enabled, model scoping applies only where the request path supplies
a model or an explicit quota bucket. Paths without either keep the same
provider-wide cooldown bookkeeping, selection and exceptions as the disabled
path, including 429 and 401 handling.

Enable with:

```text
MODEL_COOLDOWN_ENABLED=true
MODEL_COOLDOWN_MAX_SECONDS=3600
```

Disable with `MODEL_COOLDOWN_ENABLED=false`, or clear it to an empty value.
An empty maximum uses 3600 seconds. Whitespace is ignored. Malformed settings
log once per setting name, without the supplied value, and disable this feature.
The maximum must be an integer from 1 through 2147483647.

## Evidence and scope

The pool methods accept keyword-only `model`, `quota_bucket`, `outcome`,
`credential_wide_auth` and `retry_after_seconds` inputs where applicable.
Selection and observation must receive the same provider, model and quota bucket.
Use the actual upstream model, without changing an explicit model selection.
A quota bucket is an explicit provider configuration shared by its member models;
never infer it from a response body, an arbitrary caller field or a model prefix.
Model names and quota bucket names occupy distinct namespaces.

Use `UpstreamOutcome` evidence. A `throttled` credential outcome cools only
that credential and model, or its explicitly configured quota bucket.
A classified quota-exhaustion observation can also use `throttled`; a bare 402
is a classified caller error and cannot establish exhaustion. Caller errors, transport
failures, cancellation and provider failures create no cooldown.

A classified credential rejection is global only with genuine auth evidence.
Pool adapters treat a classified 401 as credential-wide unless
`credential_wide_auth=False` is supplied. A 403 needs an explicit
`credential_wide_auth=True`; endpoint/model permission denial is not enough.
A supplied classification overrides the status classification, including for
cancellation. Neither health evidence nor cooldown grants replay permission.

Trusted normalized reset advice is passed as finite nonnegative delay seconds,
relative to the observation's monotonic time. The store does not parse raw
headers or provider bodies. Invalid advice uses the existing pool's fallback:
60 seconds for throttling, 300 seconds for Codex Everywhere auth, and the
configured NanoGPT validation TTL for auth. The configured maximum caps each
observation; positive fractional delays round up only in `Retry-After`.
At least one second is retained for zero delay to prevent immediate redispatch.
Success clears only its model/bucket observation. It does not clear another
model, an auth rejection, a legacy credential-wide rest or a capacity guard.
Unscoped recording uses the legacy provider-wide rules and leaves model state
unchanged. Genuine authentication rejection on a scoped path also rests the
credential in the legacy map, using the same capped deadline, so unscoped
selection observes it.

## Selection and errors

Scoped selection excludes keys resting in either the model store or the legacy
provider-wide map. Available keys retain configured order. NanoGPT retains its existing active-key
preference, single-configured-key probe bypass, validation TTL and request-count
rules. Filtering several configured keys down to one does not skip validation.
During scoped selection, catalog probes carry no model quota evidence: only
genuine auth rejection can cool every model from that probe. Unscoped validation
keeps its legacy rejection rules. Raw and unified NanoGPT pools remain isolated.

`CredentialPool.available` returns the eligible list. `CredentialPool.select`,
`NanoGPTKeyPool.select_key` and `select_available_key` with model/bucket context raise
`ModelCooldownExhausted` when all configured eligible keys are cooling. There is
no secret dispatch, additional wait, retry or synthetic completion. An empty
configuration retains the existing no-key result. The error is a real 429 with
`error: model_cooldown`; the named Flask adapter emits bounded integer
`Retry-After` advice to the earliest eligible key's release. A credential's
release waits for both its auth and model/bucket observations to expire.

Register `cooldown_error_response` for `ModelCooldownExhausted` and
`ModelCooldownCapacity` in the Flask application. Preserve these
errors through route wrappers instead of translating them to 500/503 or a
candidate fallback. Without the adapter, the existing APIError handler does not
include `Retry-After`.

## Storage and operational limits

Model-scoped state is process-local, protected by a lock and limited to 10000 live
observations across both pool implementations. Credential IDs are SHA-256 HMACs
with a random process-local salt and provider/pool namespace. Scope labels are
also HMACs. New cooldown state stores only digests and monotonic expiry times;
it never serializes or logs keys, prompts, completions or model names.
The existing pools still retain configured/active keys for dispatch.

Expired observations are pruned on reads and writes. A process restart discards
observations and changes HMAC identities. This feature does not provide
multi-process, Container or distributed consistency. Configured credentials and
existing raw/unified pool precedence remain authoritative.

At capacity, live observations are never evicted. A scalar overflow deadline
covers the omitted observation's capped TTL. During that interval new admission
fails closed with 503 and bounded `Retry-After`; known all-cooling pools still
produce 429. This capacity failure is not a credential-wide cooldown. It may
briefly block unrelated traffic; that is the cost of preserving live cooldowns
within a hard memory bound. Observation itself cannot interrupt an already
produced response. There are no extra provider calls or charges from cooldown
tracking. Existing permitted validation probes retain their existing cost.

## Request integration

Pass the resolved upstream model and configured quota bucket to both selection
and recording. Forward classified outcomes, genuine credential-wide auth
evidence and normalized trusted reset advice to recording. For `available`
callers, an empty eligible result needs the same 429 admission decision using
`model_cooldown.select` with the original keys and legacy rest deadlines. An
empty configuration remains distinct. Preserve cooldown exceptions through
route wrappers rather than treating them as generic candidate failures.

Native Worker roleplay maintains independent health state. Worker-forwarded
Flask traffic uses these pools. Forward `MODEL_COOLDOWN_ENABLED` and
`MODEL_COOLDOWN_MAX_SECONDS` through the Container environment allowlist.
Expose `Retry-After` through Flask and Worker CORS for browser clients.
No migration, table, new production route or Worker route/module is required.

Tests cover pool selection and recording plus a registered Flask error adapter
with fake dispatch. Live provider quota semantics, deployment, billing and
distributed consistency require separate operational verification.
