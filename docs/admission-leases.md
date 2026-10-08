# Shared keyed concurrency admission

Admission is off by default. `ADMISSION_ENABLED=false` (or empty) leaves dispatch,
response bytes, headers and storage unchanged. No lease call or Durable Object access
occurs. Invalid flags or limits disable admission and produce one fixed warning per
process/isolate without the invalid value. `ADMISSION_LIMITS_JSON={}` (or empty) is
unlimited even when the flag is true. There is no default heavy-model gate.

## Limits and identity

Enable with `ADMISSION_ENABLED=true` and, for example:

```json
{"principal": 4, "model_groups": {"heavy": 1, "fast": 3}}
```

`principal` limits all active requests for one authenticated key identity across its
model groups. Each `model_groups` entry limits that same principal within the named
**authorized** group. Missing or zero limits are unlimited. Limits are integers from
0 through 10,000; at most 256 group entries are accepted. Unknown fields disable the
configuration. These are concurrency limits, not RPM, token or upstream quota limits.
Both applicable limits are checked atomically before dispatch. Lowering a limit does
not revoke existing work; new acquisitions wait for capacity.

The authentication/routing registrar supplies an `AdmissionIdentity` (Python) or an
explicit object (Worker) with `principal_hash`, `model_group`, `request_id`, and
`deadline_ms`. The principal is a stable opaque SHA-256 identity for the authenticated
key, shared between runtimes. Do not supply raw keys, usernames, caller headers or
unverified body fields. Resolve/authorize the group before admission. The request ID
must identify one generation, including both runtimes when forwarding. The deadline
is a Unix timestamp in milliseconds, after now and at most 24 hours away; the registrar
must supply the actual eventual generation deadline, not a new deadline on renewal.

## Authority and private operations

`ADMISSION_COORDINATOR` uses `AdmissionCoordinator` with SQLite Durable Object storage.
The binding and `v3_admission` migration are additive; existing bindings/migrations
stay unchanged. The class is inert while disabled: construction, fetch and alarm make
no storage writes and schedule no alarms. Limits for a principal share one of 64
stable shards, selected from its hash, so native Worker and Flask callers compete for
the same capacity. Each shard holds at most 10,000 outstanding leases, independent of
configured per-principal limits. This safety bound also returns 429.

The fixed Container egress endpoint is `POST http://intelligence.internal/v1/admission`.
Container egress isolation is its authentication boundary, as with the other private
intelligence operations. It must remain absent from the public Worker router. Native
Worker hooks call the bound authority directly, after authentication. Durable Object
fetch accepts only `POST http://admission.internal/v1/admission`; it is not a public
HTTP authority. A public origin, query, fragment, alternate method, unknown field or
client-supplied limit/key is rejected. The strict version-1 body contains the identity
fields and `operation` (`acquire`, `renew`, `release`); renew/release also require
`lease_id`. Lease IDs cannot release or renew another principal, group, request or
deadline. Repeated acquisition of a live request returns its existing lease without
extending it; changing the group/deadline is rejected. Release is idempotent.

Standalone Flask has no global local semaphore. It needs an explicit private
`ADMISSION_AUTHORITY_URL`, for example `http://127.0.0.1:8081/v1/admission`, pointing to
a trusted private adapter implementing these same shared authority operations. That
adapter is an integration requirement, not provided as a public Flask route here.
Only private IPs, localhost or `.internal` hostnames with `/v1/admission` are accepted;
credentials, redirects, query strings and fragments are forbidden. The adapter must
be isolated/authenticated at the network or service boundary. Missing authority while
limited and enabled fails with 503. Container D1 mode uses the fixed private egress
URL by default. Explicit URLs take precedence. Requests bypass environment proxies,
use one POST with no retries, 2-second connect/3-second inactivity timeouts, and bound
response decoding to 4 KiB and a 5-second decoding budget. The Requests timeout is
not a hard overall wall-clock deadline during a stalled setup. Worker authority calls
have a 5-second wait bound; a lost reply is never permission to replay generation.

## Lease lifecycle

A lease lives for 30 seconds, capped by the generation deadline. Renew every 10 seconds.
Python has one lazy daemon renewal scheduler per process, shared by clients, with
bounded local lease bookkeeping. It performs private operations sequentially, so very
large active sets or a slow authority can cause leases to expire; it never admits on
that basis. Worker leases own a renewal timer and an expiry timer. Renewal cannot
extend the generation deadline or revive an expired lease. Lost renewal stops further
output and calls the injected cancellation collaborator. Wire `on_lost` (Python) or
`onLost` (Worker) to the actual upstream cancellation owner. A blocking dispatch cannot
be forcibly interrupted by a lease helper without that collaborator.

`dispatch_with_admission(identity, dispatch, client, on_lost=...)` wraps a normalized
Flask Response; `runWithAdmission(identity, env, dispatch, options)` wraps native Worker
dispatch. Worker options accept the request `signal`, `onLost`, and an injectable
millisecond clock. Use one lifecycle owner per generation. Forwarded work must be
admitted by Flask only; the Worker must not acquire an additional lease for forwarding.
A pre-dispatch/preflight rejection, response construction failure, normal completion,
stream error, disconnect or deadline releases once. Streaming wrappers pass chunks
unchanged and do not buffer the full response. Closing a Flask stream before its first
iteration still closes its source and releases its lease. WSGI detects disconnects
only on writes/iteration/close; cancellation during blocking setup needs the transport
collaborator. Release failure is not replayed and does not rewrite provider output;
the authority reclaims the slot at lease expiry. A process crash has the same bound.

Expired leases stop counting immediately and are removed on the next authority
operation using an expiry index. No cleanup alarms are scheduled. An idle shard may
retain expired metadata until its next operation. Only opaque principal identity,
authorized group, request ID, lease ID, deadline and expiry are stored; no request,
prompt, response, tool content or credential is stored or logged. SQLite records and
private calls incur normal platform storage/request costs. Admission does not claim
zero generation cost, successful output or replay permission after a partial result.

## Errors and integration

Capacity denial is a real 429 `admission_denied` with integer `Retry-After` seconds
until the earliest blocking lease expiry (minimum 1). Unavailable authority/storage or
unconfirmed acquisition while enabled is 503 `admission_unavailable`. Lease identity
mismatch is 403; expired renewal is 409 on the private API, translated to 503 by the
generation lifecycle. No success body is synthesized. Error responses are no-store.
Raw provider headers are preserved; only gateway denial adds Retry-After.

Native Worker generations acquire their lease at the edge. Requests forwarded to the
Container acquire only in Flask, after authentication and before dispatch, so one
request never holds two leases. No public route is added; `/v1/admission` exists only
on the private intelligence transport. Set `ADMISSION_ENABLED`, `ADMISSION_LIMITS_JSON`
and, for a standalone Flask deployment, `ADMISSION_AUTHORITY_URL` on both the Worker and
the Container. No D1 tables are added. `wrangler deploy` applies the `v3_admission`
Durable Object migration; the class stays inert until the flag is enabled.
