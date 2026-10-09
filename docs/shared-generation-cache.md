# Shared exact generation cache

The default settings keep the existing process-memory cache:

```text
GENERATION_CACHE_BACKEND=memory
GENERATION_CACHE_SHARED_ENABLED=false
```

To share exact complete Chat Completions responses between Container instances and native Worker requests, apply `intelligence-migrations/0019_generation_cache.sql`, then set:

```text
GENERATION_CACHE_BACKEND=d1-r2
GENERATION_CACHE_SHARED_ENABLED=true
```

Each caller must also send `X-MultiLLM-Cache: on`. Both settings and the request header are required. Empty settings use the defaults; malformed settings disable shared caching and emit one content-free warning. `RESPONSE_CACHE_ENABLED=false` disables the Flask response cache. Native caching applies to supported native Chat Completions endpoints; other native protocols and raw requests without the header retain their normal transport. Flask and native caches have separate policy identities and do not reuse one another's entries.

Authentication, key scopes, model permission checks and retention policy run before lookup. Identity includes the canonical full request, authenticated principal and key digest, route, model, effective server policy and workflow version. Native identity also includes the upstream endpoint, protocol organization/project headers and current configuration revisions when revision synchronization is enabled. Requests with ambiguous provider-selection headers, separate upstream credentials, session identifiers or query parameters bypass shared caching. Policy changes during lookup prevent replay; changes during dispatch prevent storage.

Eligible requests are deterministic (`temperature: 0` or an integer seed), nonstreaming and single-choice. Tools or legacy functions must be absent or disabled with `tool_choice: none`. Only an HTTP 200 JSON response with a complete finish reason and no runnable tool output is stored. Errors, partial, filtered, malformed, streaming and oversized results are never stored. There is no semantic similarity matching or automatic request replay.

An eligible response carries `X-MultiLLM-Cache: hit` or `miss` and `X-MultiLLM-Cache-Backend: d1-r2`. Hits also carry `Age`, `X-MultiLLM-Usage-Basis: cache-served` and `X-MultiLLM-Provider-Calls: 0`. The original body is preserved, including any original provider usage. Those original counts do not describe a new provider call. Accounting records the replay with a cache cost basis and zero new provider cost; it does not claim the original generation was free. Optional native ledger recording still requires `NATIVE_EDGE_METRICS_ENABLED=true`.

`Cache-Control: no-store` bypasses reads and writes. `no-cache` or `X-MultiLLM-Cache: refresh` requests fresh dispatch; `max-age` can restrict acceptable entry age. Zero-content retention bypasses before content is read from or written to shared storage. It applies prospectively and does not erase entries from earlier requests.

## Storage and failures

Metadata lives in the `generation_cache` D1 table. Response bodies use the existing `multillm_media` R2 binding under `generation-cache/v1/`. No additional binding is required. Each principal is limited to 512 live entries and 16 MiB of live response bodies. One body may contain at most 1 MiB. TTL is 300 seconds. Transactional capacity checks reject new writes when full and allow replacement of an existing key within the byte budget. Full caches continue ordinary dispatch.

R2 pointers are immutable and scoped to principal and exact key. Reads validate the body size, digest, metadata and completion shape. Missing or corrupt bodies are misses. Native storage reads and writes wait at most two seconds per operation; the Container private transport waits at most three seconds. The private `POST /v1/state/generation-cache` endpoint accepts only fixed `get`, `put` and bounded `prune` operations on the existing internal outbound transport. It is unavailable when shared caching is disabled. Missing bindings or schema return a sanitized JSON HTTP 503 from this private endpoint. Chat cache failures continue normal dispatch and preserve its actual response; no success is invented and no upstream retry is added.

## Expired objects

Schedule bounded calls to `cleanupGenerationCache(env, {limit: 100, cursor})` from the storage module, or the equivalent private `prune` operation. Continue with the returned cursor until it is null. Cleanup removes expired metadata and objects only under `generation-cache/v1/` with an expired `expires_at` custom metadata value. It never deletes unrelated media objects. Replaced and orphaned bodies expire after their original 300-second TTL, so physical bucket usage can temporarily exceed the live per-principal metadata budget until cleanup runs. R2 and D1 storage operations can incur their normal service charges. Migration deployment and scheduled cleanup are operator actions; enabling the feature does not apply SQL or install a schedule.
