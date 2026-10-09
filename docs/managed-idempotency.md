# Managed request idempotency

`MANAGED_IDEMPOTENCY_ENABLED` defaults to `false`. Empty values retain that default;
malformed values disable the feature and emit one warning without the value.
Without an `Idempotency-Key`, existing requests and responses are unchanged.
Raw provider routes bypass idempotency claiming and keep their existing header
forwarding rules: raw OpenAI chat drops `Idempotency-Key`; providers whose header
allowlists support it submit the caller's key unchanged once. When disabled,
the intelligence gateway keeps its existing `idempotency_not_supported` rejection.

Enable the setting in the Worker and Container after applying
`intelligence-migrations/0023_idempotency.sql`. The private authority requires
`INTELLIGENCE_DB` and the existing `multillm_media` R2 binding. Missing migrations,
bindings or private authority return HTTP 503 `idempotency_store_unavailable`
before generation. There is no process-local fallback.

For a managed nonstreaming chat request, send a stable key:

```http
POST /intelligence/v1/chat/completions
Idempotency-Key: order-123
Content-Type: application/json

{"messages":[{"role":"user","content":"Summarize this order."}],"stream":false}
```

Keys contain 1 to 128 ASCII letters, digits or `._:/+@-`. The identity is scoped to
the authenticated principal, HTTP method and path. A normalized JSON digest binds
the body, requested model, routing policy and retention revision to that key.
Object key ordering and insignificant whitespace do not change the digest.
Changing the request or policy under a claimed key returns HTTP 422
`idempotency_key_conflict`. Different principals and paths have separate claims.

An atomic claim precedes admission and dispatch. Concurrent identical submissions
receive HTTP 409 `request_in_progress` with `Retry-After: 1` while the owner runs.
A completed response replays the stored status, body bytes and bounded content
headers, with `X-MultiLLM-Idempotency: replayed`. Replay does not reserve usage or
call a provider. Streaming keyed requests return HTTP 400
`idempotency_stream_unsupported` before claiming or dispatching.

A timeout, abandoned request, failed completion write or lost outcome blocks the
key. Later submissions receive HTTP 409 `outcome_unknown`; they never start another
generation. A dispatch acknowledgement is recorded before provider handoff. Claims
that remain unfinished for one hour become unknown when accessed. Existing
provider refusal/fallback rules are unchanged; idempotency grants no new retry
permission. An unknown outcome can still incur provider charges and retain the
existing usage hold. A new key can create a separate billable generation and is
not a safe way to recover an unknown outcome.

Responses are bounded to 1 MiB, with at most 32 selected headers and 16 KiB of header
metadata. Response bytes live under `managed-idempotency/` in R2; D1 contains only
hashed identity, ownership, state, expiry and an integrity-checked object pointer.
Successful responses above the bound are returned normally but cannot be replayed;
the key becomes unknown. Errors and partial results are never stored as successes.
The zero-content retention policy also prevents response storage and replay.

Replay content expires 24 hours after claim. Expiry, missing objects or failed
integrity checks block replay rather than authorizing another generation. Hashed
claim tombstones remain to prevent ambiguous key reuse. Expired objects are removed
when their key is accessed; operators should also configure an R2 lifecycle rule for
this prefix to remove expired and orphaned content. Expiry does not erase usage
records or release unknown usage holds. No prompt or response content is logged.

The Flask registration point is `middleware.idempotency.register_idempotency`.
Register its named `idempotency_request_hook` after authentication, retention and
secret policy and generation deadlines, and before admission. Intelligence dispatch finalizes only after
validated nonstream completion. Other managed chat dispatchers supply their resolved
policy through `policy_revision` and call `dispatch_with_idempotency` with an explicit
completion classifier. The optional `settlement` callback receives classified state,
without response content or permission to generate. The private managed-state
dispatcher keeps idempotency at `/v1/managed-state/idempotency`. Reservations use
the separate `/v1/reservations` endpoint, and tool grants use model-state operations;
the managed-state reservation and tool-grant injection points remain unused.
