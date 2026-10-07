# Verified Knowledge answer memos

## Purpose and integration

Share verified excerpt bundles across principals and unrelated corpus generation
changes. The layer runs inside `retrieveKnowledge` after authorization and the
current catalogue/policy read, before cache, index or provider work. Lookup is
only for `freshness: "normal"`; fresh retrieval can populate a verified memo.
The existing principal/generation/policy cache remains a fallback.

## Storage and bounds

`KnowledgeMemos` is a SQLite-backed Durable Object bound as `KNOWLEDGE_MEMOS`.
Its appended migration tag is `knowledge-memos-v1`; existing migration tags are
unchanged. The namespace uses `idFromName("personal")`. Rows are logically
sharded by normalized product, with the empty product selecting unscoped queries.

This deliberately uses one object rather than an object per product. A strict
20,000 global LRU limit and atomic all-product purge otherwise need coordination
and eviction across independent objects, with partial-failure and concurrency
recovery. A single SQLite transaction is the closest bounded alternative for this
personal gateway. The tradeoff is shared throughput and a single storage ceiling;
future physical sharding would need a transactional global capacity protocol.

Each record contains `id`, `created_at`, `last_hit_at`, `hits`,
`key: {product, version, repository}`, original `query`, `query_norm`, `mode`,
`token_budget`, `embedding`, `bundle` and `citations`. The stored bundle excludes
`usage`, `served_at`, `memo` and any observed memo candidate. `bundle.token_count`
is indexed separately for budget-fit lookup. Citations contain immutable
`artifact_id`, SHA-256 `content_hash` and `expires_at`.

Embeddings use `@cf/baai/bge-m3` through `KNOWLEDGE_SEARCH_AI`, quantized into at
most 1,024 signed 8-bit values plus a scale. JSON persists those values; the active
product's vectors load lazily into an Int8Array cache, bounded at 2,000 entries.
A product switch rebuilds that cache. Mutations invalidate it and deletions remove
entries. Cosine is invariant to positive vector scale.

Bundles larger than 256 KiB are rejected; dispatch envelopes are limited to
320 KiB. Per-product capacity is 2,000 and total capacity 20,000. Put, product
LRU eviction and global LRU eviction share one synchronous SQLite transaction.
Eviction sorts by last hit, creation time and identity. Hit counts and last-hit
timestamps persist across object restarts. Stats group at most 20,000 products.

## Lookup and verification

1. Exact lookup lowercases the query, collapses whitespace and removes trailing
   Unicode punctuation. Product, exact version, repository and mode must match;
   stored token count must fit the new request budget. An exact hit needs no
   embedding or provider calls. The complete exact path (lookup, validation and
   hit accounting) is bounded to 300 ms; timeout is a miss.
2. Semantic lookup embeds once per request and scans only vectors for the same
   product/version/repository/mode and fitting budget. Cosine must meet the
   configured threshold. In semantic `on` mode, embedding, matching, validation
   and hit accounting share a 400 ms total deadline before retrieval. Timeout,
   invalid or unavailable embeddings are a miss.
3. A candidate must be younger than the memo TTL. One batched authority
   transaction verifies every citation using the same shared eligibility predicate
   as retrieval and cached answers: artifact exists and is not expiring, source
   is enabled, provider is enabled with retention allowed, and canonical URL remains
   allowed. Retained live (unpublished) artifacts are eligible; only published
   artifacts must be the source's current revision. Hashes must match and both
   citation and artifact must be unexpired. The transaction also fences the current
   policy revision.
   Invalid candidates are deleted and normal retrieval continues.
4. Exact or enabled semantic hits update hit statistics and serve a cloned bundle
   with the new query, fresh `served_at`, `elapsed_ms`, `path: "memo"`, no newly
   used evidence providers and only this request's usage. Metadata is
   `memo: {kind, similarity, age_seconds}`; semantic adds `matched_query`.
   MCP trims bookkeeping while preserving `memo` and observed candidates.

Semantic observe mode starts embedding and matching concurrently with ordinary
retrieval and never waits for them. It validates a candidate but never serves it
or increments its hit counter. If the candidate has finished by bundle assembly,
the normal response adds
`index_diagnostics.memo_candidate: {similarity, matched_query, age_seconds}`.
A later completion is ignored; observation is bounded to two seconds in the
background and retained with `waitUntil` when available.

## Writes and failures

Store only `ok`, or `partial` with excerpts and no failure flagged by retrieval.
Stable coverage limitations can be retained; provider, source, index or scheduling
failures cannot. Provider-context-only answers cannot create memos.
Before storing, validate the cited manifests with the same batched authority
operation. Retained live artifacts can back memos before publication under the
same rule as cached answers. Publishing that artifact preserves eligibility;
a later published replacement invalidates its memo backing.

A small replaceable local function rejects private-key headers and common key
prefixes. Such queries perform neither memo lookup, embedding nor writes.
Record validation repeats the guard and enforces payload, vector and citation
bounds. Normal cache hits can populate memos after validation.

When `waitUntil` is available, the whole write (validation, embedding and put)
runs in the background; returning the answer waits for none of those stages.
Without `waitUntil`, tests await the whole write. Writing shares a two-second
ceiling across its stages. Foreground writes also leave 100 ms before the existing
24-second retrieval deadline; background writes have their own deadline and may
outlive the response. Memo exceptions, binding faults, background-registration
failures and embedding timeouts never turn successful retrieval into an error.
Ordinary retrieval still enforces its existing request deadline.

Workers AI embeddings have no existing reservation tariff in this gateway.
Each attempt records provider `workers_ai`, zero `bound_units`, outcome
`completed` or `unconfirmed`, and measurement `unmetered_platform_operation`.
Response usage is a snapshot of work started by return time: an unfinished
embedding is `unconfirmed`, and a background embedding started later is not
retroactively appended. Background embeddings remain zero-unit operations.
These units are not a cost estimate; Cloudflare billing applies. Exact hits record
no embedding usage and semantic lookup/write reuse one embedding attempt.

## Policy and management

| Field | Values | Default |
| --- | --- | --- |
| `memo_exact` | `on`, `off` | `on` |
| `memo_semantic` | `off`, `observe`, `on` | `observe` |
| `memo_similarity` | finite number 0.85–0.99 | 0.92 |
| `memo_ttl_hours` | integer 1–720 | 72 |

Existing policies gain defaults when read; API/MCP schemas and dashboard controls
retain explicit settings when updating a complete revision-protected policy.
Both controls off disables memo work.

`knowledge_memos_stats` accepts `{}`; `knowledge_memos_purge` accepts
`{product?: string, all?: boolean}`. Both require `knowledge:manage` and belong to
the manage toolset. Stats return per-product count, hits, oldest/newest creation
and totals/limits. Purge returns the number removed and atomically clears storage
and vectors. Empty product addresses unscoped queries; `all: true` addresses all
products. A purge requires an explicit target and rejects product plus all true.

REST exposes `GET /v1/knowledge/memos` and `DELETE /v1/knowledge/memos`, mirrored
in Flask and the main Worker edge. DELETE accepts JSON or query parameters, with
strict boolean conversion, no duplicates/unknown fields and no mixed body/query.
GET rejects query fields. The private Knowledge Worker dispatches `memos.stats`
and `memos.purge`; the generated MCP catalogue includes both tools. A missing
memo binding makes management unavailable while ordinary retrieval continues.

## Verification and rollout

Synthetic tests cover exact cross-principal reuse, corpus generation independence,
semantic observe/on/off and below-threshold behavior, target/mode/budget separation,
hash/current-revision/expiry/TTL and policy revocation, fresh bypass, failure and
secret guards, payload bounds, LRU, stats/purge/scope checks, Flask/edge REST/MCP
parity, trimming, policy serialization, full background writes, concurrent
observation, immutable returned usage and 300/400 ms deadline fail-open behavior.
Local Miniflare exercises the actual SQLite Durable Object, concurrent hit updates,
restart persistence and purge. Catalogue generation/check and Worker regression
suites are required.

Deploying later requires the committed binding and new SQLite DO migration. No
D1 migration, new secret or variable is needed. The existing AI binding must
support bge-m3 for semantic behavior; otherwise exact memos still work. Review
observe diagnostics before enabling semantic serving. Tests establish local
behavior; deployed AI support, latency, billing and browser journeys require
separate operator verification. No deployment is part of this change.
