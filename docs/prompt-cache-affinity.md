# Outcome-bound prompt cache affinity

Prompt cache affinity is disabled by default. Enable it for authenticated managed
automatic text routes with:

```sh
PROMPT_CACHE_AFFINITY_ENABLED=true
PROMPT_CACHE_AFFINITY_TTL_SECONDS=900
```

Disable it with `PROMPT_CACHE_AFFINITY_ENABLED=false`. An empty value uses the
default. TTL defaults to 900 seconds and accepts integers from 1 to 86400.
Malformed settings disable affinity and produce one warning naming the setting
without its value. Disabling affinity preserves request and response bytes,
headers, credential order, and retry behavior.

The managed Chat Completions route and automatic aliases translated through
Responses or Messages observe the credential that actually served an attempt.
A successful complete response binds that provider/model and credential. Stream
headers and early content do not bind: the observer waits for terminal protocol
evidence and normal exhaustion. Failed, incomplete, interrupted, and cancelled
responses evict only the matching binding. Affinity adds no retry permission.
Explicit models, raw proxy paths, and native roleplay keep their existing behavior.
This integration covers stored ordered automatic aliases. The intelligence
gateway uses a separate transport and does not consume this request scope.

Credential preference only considers keys that the pool already allows. Model
cooldown, credential rest, grants, budgets, context capability, and fallback
eligibility remain authoritative. Ordered automatic routes retain their configured
provider order. A tier-aware scheduler can call `AffinityScope.order_candidates`
with its already eligible ordered models and approved tier map. Preference can
only move a successful candidate within the first eligible tier. Missing tier
evidence retains the original order. This interface does not authorize candidates
or retries, and it never crosses a fallback tier during tool loops.

Bindings are isolated by authenticated tenant/principal, session, role lane,
automatic route, reusable opening prefix, tool schema, and policy revision.
Changing route configuration or the supplied policy revision invalidates an old
binding. Credential removal and cooldown invalidate its key preference. Explicit
session IDs do not replace prefix checks; subsequent turns and tool results keep
the opening identity. The final observer captures an opaque credential fingerprint.
No prompt, response, principal, session ID, or credential plaintext is persisted
in the affinity map or logged by this feature.

Storage is a process-local LRU capped at 10000 entries. TTL is monotonic and is
not extended by reads. Expired entries are removed on access and insertion. A
restart loses bindings; multiple Containers have independent maps. Cross-instance
affinity is best effort, and there is no D1 migration or distributed consistency
claim. The bounded stream parser ignores oversized lines and cannot bind a JSON
body larger than 1 MiB without other completion evidence. Unknown completion
evidence declines to bind; it never fabricates a success body or changes the
original error returned to the client.

The observer consumes provider cache-read usage through the existing prompt cache
usage buckets. Counts remain measured when the provider reports them. Read cost
and rebuilding the same tokens at ordinary input prices are explicitly named
estimates derived from configured catalog prices; absent counts or prices remain
unknown. These observations do not prove savings on every request, do not change
budget accounting, and never update routing policy automatically. Provider cache
retention and billing still follow that provider's contract.
