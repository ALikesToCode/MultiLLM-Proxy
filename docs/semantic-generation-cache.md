# Scoped semantic generation cache

Semantic reuse is off by default. `SEMANTIC_CACHE_ENABLED` defaults to `false`, and
`SEMANTIC_CACHE_POLICY_JSON` defaults to `{}`, which opts in no routes or keys.
Empty environment values mean these defaults. Invalid configuration disables the
feature and emits one warning without the supplied value. The exact response cache
keeps its existing opt-in and behavior when semantic reuse is disabled or unscoped.

To disable semantic reuse:

```text
SEMANTIC_CACHE_ENABLED=false
SEMANTIC_CACHE_POLICY_JSON={}
```

To opt in the authenticated Chat Completions route:

```text
SEMANTIC_CACHE_ENABLED=true
SEMANTIC_CACHE_POLICY_JSON={"routes":["/v1/chat/completions"],"embedding_model":"openai:text-embedding-3-small","revision":"1","model_revision":"1","allow_tools":false,"allow_streams":false}
MODEL_PRICING_USD_PER_MILLION={"openai:text-embedding-3-small":{"input":0.02,"output":0}}
```

Pricing values are operator-supplied USD per million tokens, not a price catalog.
Preserve the other model entries in an existing pricing configuration. The embedding
model must be an explicit `provider:model` already configured in the gateway. No new
provider credentials, origins or bindings are introduced. Use `keys:["account-id"]`
to opt in an authenticated account ID, or its username when it has no ID. These are
server-authenticated identities, not raw API keys. Route and key opt-ins are combined
with OR. Worker routes use their full route name, such as
`/codex-easy/v1/chat/completions`, rather than the upstream path.

Only `allow_tools:false` and `allow_streams:false` are supported. Either option set to
`true` is invalid configuration and disables semantic reuse. Tool definitions, tool
results, function calls, streams and requests for more than one choice are ineligible.
Only direct, explicitly selected Chat Completions models are supported; automatic and
cascade routes bypass semantic reuse. The last message must be a nonempty user text.
Dynamic state, provider-selection headers and ambiguous upstream credentials bypass
reuse. Existing exact caching remains independent for these requests.

## Compatibility and fact checks

Reuse requires exact matches for the authenticated principal and presented key,
provider, model, route, system prompt, earlier turns, every request field apart from
the final user text, sampling parameters, seed, response/output schema and policy
revisions. Grants, secret policy and retention participate in the compatibility
identity. Organization, project and protocol headers also partition responses.
Change `revision` after changing a compatibility policy, and `model_revision` when
the configured embedding model changes without changing its name.

The final user text alone is embedded. Cosine similarity must be at least 0.98.
A matching vector is insufficient: the two texts must have the same ordered numbers,
dates, English month/weekday names and number words, negation words and exact quoted strings. Their protected facts are stored only
as a digest. Changing a number, a date, `not`, `never`, a negative contraction, or quoted
text prevents replay. Recognized volatile terms such as `today`, `now`, `current`,
`latest`, `weather` and `stock` bypass semantic reuse. These conservative lexical checks
cannot prove factual equivalence; opt in only routes whose answers tolerate paraphrases.

## Spending and provenance

Embedding input is limited to 1,024 estimated tokens (4,096 UTF-8 bytes). Oversized
inputs bypass lookup without truncating the user's question. A lookup is skipped if
embedding pricing is unknown, or if the conservative 1,024-token exposure including
a flat request price exceeds $0.001. Every dispatched embedding is separately recorded
through usage accounting, including misses and failed embeddings. Provider token counts
are used when present; otherwise accounting uses the conservative estimate. Embedding
permissions and budget admission apply before dispatch. No warmup generations run.

A hit replays the complete stored JSON bytes with:

```text
X-MultiLLM-Cache: semantic-hit
X-MultiLLM-Cache-Backend: semantic-d1-r2
X-MultiLLM-Usage-Basis: cache-served
X-MultiLLM-Provider-Calls: 0
Age: <seconds>
```

The generation ledger records zero generation cost and cache provenance. The separate
embedding charge still applies. Stored provider token usage remains in the original
JSON response; the provenance headers explain that it describes the stored generation.
`Cache-Control:no-store` bypasses lookup and storage; `no-cache` and the existing
`X-MultiLLM-Cache:refresh` force a generation. `max-age` can further restrict replay age.

## Storage and failures

Apply the additive `0026_semantic_cache.sql` migration before enabling the feature.
D1 holds `semantic_generation_cache`, with scoped digests, a bounded vector, embedding
revision, expiry, integrity hash and body pointer. It scans at most 256 scoped entries
exactly; Vectorize is not used. The private transport returns the four best compatible
candidates to bound response size even for large vectors. A corrupt body among these
candidates can reduce reuse without changing normal dispatch. Complete successful single-choice JSON responses of at
most 1 MiB are stored in the existing `multillm_media` R2 bucket under `semantic-cache/`.
The exact cache's separate capacity policy does not provide semantic oldest-entry
replacement, so semantic bodies use their own prefix.

Entries expire after 300 seconds. D1 transactions evict the oldest entries to keep at
most 256 per principal, across all partitions. Replaced or evicted bodies stay immutable
until expiry so concurrent readers remain safe. Bounded maintenance removes expired
metadata and R2 bodies without touching another prefix. Missing, corrupt, foreign or
expired bodies never replay. Request cancellation and policy changes prevent reuse
or storing an in-flight result. Responses with errors, truncation, tool calls or
`Cache-Control:no-store` are not stored.

Zero-content retention bypasses semantic embedding, lookup and storage entirely.
Retention controls must be enabled for the gateway to honor a zero-retention request.
A missing enabled schema returns JSON HTTP 503 with `error:semantic_cache_schema_missing`
before embedding or generation. Ordinary cache or embedding failures fall through to
normal dispatch once; they never fabricate a success or grant a generation retry.

## Runtime interfaces

The Flask Chat Completions cache decorator handles semantic lookup and storage. Its
fixed private transport uses `/v1/state/semantic-cache` on `intelligence.internal`.
The private Worker state dispatcher must pass validated operations to
`handleSemanticCache`. This private handler is not a public route.

Native Worker integrations use `prepareSemanticCache` after authentication, retention
and policy admission. Call `lookup` before generation and return any resulting response,
including a schema error. Call `store` only after classified successful finalization;
its required `canStore` callback must return `true` only for complete, classified success.
Missing classification prevents storage. A hit uses
`semanticCacheServedEvent` instead of provider generation telemetry. Supply named
`embed`, `embeddingAllowed`, `reserveEmbedding` and `accountEmbedding` collaborators
from the existing configured embedding transport, grant checks, budget reservations
and usage ledger. The embedding transport must honor its abort signal and must not
introduce retries or caller-selected origins. `accountEmbedding` settles the reservation
according to `submission_outcome` (`before-dispatch`, `response` or `unknown`);
unknown submissions retain their hold. All four collaborators are required; a missing
collaborator bypasses lookup. `reserveEmbedding` returns `false` to deny admission,
or a reservation (including `null` for an unbudgeted principal). Embedding and private
storage operations have two-second deadlines in the Worker.
Use `cleanupSemanticCache` in scheduled maintenance. The Worker module does not mount
public routes or automatically select a provider transport.
