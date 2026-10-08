# Zero-content retention

`CONTENT_RETENTION_ENABLED` defaults to `false`. While off, the retention header
and policy JSON are ignored. Cache, sampling, roleplay, memo and handoff behavior
stays unchanged. An empty flag means off; an empty policy means `{}`.
Malformed settings disable these controls and log a warning once per setting,
without logging its value. Invalid configuration therefore does not provide a
retention guarantee: validate settings before enabling the feature.

When enabled, `CONTENT_RETENTION_POLICY_JSON` accepts this shape:

```json
{
  "default": "inherit",
  "keys": { "verified-key-id-or-sha256": "zero" },
  "routes": { "/v1/chat/completions": "zero" }
}
```

Each value is `inherit` or `zero`; route matching is exact. Key selectors are
server-authenticated account IDs (username when no ID exists) or SHA-256 digests
of the authenticated presented key. Use a key digest for individual keys within
one account. Never put raw keys in the policy. The tightest default, key, route
and header wins. `X-MultiLLM-Retention: zero` tightens the policy;
`X-MultiLLM-Retention: inherit` and unknown header values cannot loosen it.

For example, with the flag off, `X-MultiLLM-Cache: on` still caches an eligible
completion even if the caller sends `X-MultiLLM-Retention: zero`. With the flag
on and policy `{}`, that same retention header bypasses both cache reads and
writes, and bypasses shadow sample construction before a stream collector or
background queue can capture content. With a configured zero key or route,
sending `inherit` still bypasses retention.

Zero roleplay turns use fresh request-local conversation state. Callers must
supply the conversation history needed for each turn. They cannot recover a
durable conversation, import a branch or use operator memory under that policy.
Turn responses expose `X-MultiLLM-Retention: zero` and
`X-MultiLLM-Roleplay-Recovery: unavailable`. Recovery returns HTTP 409 with
`recovery_unavailable`; memory operations return HTTP 409 with
`retention_forbidden`. Errors and completion bytes otherwise keep their existing
meaning. No replacement completion or new retry permission is introduced.

Only numeric roleplay counters, bounded numeric model observations and hashed
request/model identities are written to a separate counter record. Content-free
traces exclude parameter receipts, retain at most 30 turns, and write separately
from existing traces. Zero turns neither populate the conversation cache nor
refresh the existing session deletion alarm. Old content, checkpoints, recovery
records and alarms are left in place; an already scheduled alarm can still run
under its original lifecycle. The feature does not scan or delete stored data.

Knowledge memo lookup, embeddings, bundle construction and background writes are
disabled for zero requests. A derived handoff save returns HTTP 409
`retention_forbidden` before parsing or SQL mutation. It returns no saved ID.
Explicit source-corpus ingestion remains separately authorized and is unaffected.

The gateway must still hold and send content while serving a request, including
streaming and existing turn scheduling. Usage, cost, security and health counters
continue; provider calls can incur their normal cost. This is a prospective
gateway storage policy, not a provider-side retention agreement, secure memory
erasure, deletion API or prohibition on caller-authorized corpus storage. It does
not change provider prompt-cache settings or cover media storage and future
state/batch features; those features must adopt the same policy explicitly.

## Where the policy applies

- Flask resolves the policy after authentication and before cache and dispatch
  hooks, and exposes it as `g.multillm_retention_policy`. The chat response cache
  and shadow sampling check it before reading, writing or queueing content.
- The Worker resolves the policy only from the verified key identity and the
  public request path. It ignores identity in caller payloads and caller-set
  `X-MultiLLM-Retention-Key-ID`, `X-MultiLLM-Retention-Key-Hash` and
  `X-MultiLLM-Retention-Route` headers, and sets those headers itself for
  roleplay turns, operator recovery and memory requests. The bootstrap admin
  uses the trimmed `ADMIN_USERNAME` (default `admin`); the dedicated roleplay
  key uses `roleplay`. Both also match the SHA-256 digest of the verified key.
- Knowledge retrieval uses a non-storing cache for zero requests. Handoff saves
  are rejected before content is serialized into a Durable Object call.
  Knowledge requests sent from the Container carry the policy resolved for the
  authenticated Flask request, and the Container rejects zero-retention handoff
  saves with HTTP 409 before secret scanning or transport.
- Set `CONTENT_RETENTION_ENABLED` and `CONTENT_RETENTION_POLICY_JSON` on both the
  Worker and the Container. No routes, D1 tables or migrations are added.
- Browser clients can send `X-MultiLLM-Retention` and read
  `X-MultiLLM-Retention` and `X-MultiLLM-Roleplay-Recovery`.

Any feature that stores content must check the same policy before it builds a
record, queues content or persists it.

Tests use fake providers and storage. They do not verify a deployment or
provider-side retention.
