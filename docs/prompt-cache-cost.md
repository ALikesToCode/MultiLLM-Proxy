# Prompt cache usage and price buckets

`PROMPT_CACHE_USAGE_BUCKETS_ENABLED` defaults to false. Empty values use the default.
Malformed flags or metadata disable buckets and produce one warning per setting without its value.
Disabled deployments use the existing rows, SQL, costs and protocol usage translations; migration 0016 is unnecessary.

Enable with `PROMPT_CACHE_USAGE_BUCKETS_ENABLED=true` after applying `0016_usage_buckets.sql`.
`MODEL_PRICING_USD_PER_MILLION` keeps input/output/request prices and accepts explicit
`cache_read` and `cache_write` prices per million tokens. For example:

```json
{"openai:example":{"input":2,"output":8,"cache_read":0.5,"cache_write":3}}
```

`PROMPT_CACHE_PRICE_METADATA_JSON` defaults to `{}`. It may supply missing bucket prices
for an explicitly priced model, using the same model keys and price names. Explicit
prices win, including zero and invalid prices. Metadata alone cannot price a model.
No provider-wide discount factors are assumed.

OpenAI prompt/input counts include cache tokens. Anthropic input counts exclude reads
and writes. Only these explicit usage conventions are normalized; unknown cache reads
remain null. An OpenAI adapter has no cache-write category unless `cache_write_tokens`
is explicitly reported. Ordinary input is null when the inclusive total cannot safely
be split. Negative, boolean, string and counts above 2^53-1 remain unknown.
SSE observations merge valid components across events with a 64 KiB line bound.

Rows add nullable ordinary-input/cache-read/cache-write counts alongside the existing
output count, four costs in microUSD, `bucket_basis` (measured/estimated/unknown) and
`bucket_source` (openai/anthropic/request_estimate/unknown). No missing count becomes
zero. A measured zero costs zero without a price. Unknown positive-count prices leave
the total null while known component costs remain visible. Decimal arithmetic is bounded
at 10^12 microUSD per component and total (one million USD). Costs may contain fractional
microUSD; totals are computed before conversion to floats. Estimates are not invoices.
Gateway response-cache hits have no provider charge.

SQLite adds nullable columns locally only when enabled and keeps old rows readable.
The control-plane PostgreSQL adapter also adds nullable columns when enabled; it has
not been validated against a live PostgreSQL database. D1 needs migration 0016 before
enabling the feature. The migration adds nullable columns to the existing `usage_events`
table and never replaces it.

In D1 mode the Worker's private ledger writes the bucket columns in the same batch
transaction as the base row, with the same batch guard and daily rollups. If the
extended write fails, the base row is still saved and the call returns HTTP 503 JSON
`usage_buckets_unavailable` with `cache-control: no-store`. A retry with the same batch
ID does not duplicate the base row. This is a private storage error, not a reason to
replay generation. Set `PROMPT_CACHE_USAGE_BUCKETS_ENABLED` on both the Worker and the
Container. Native Worker generations record base usage only, without cache buckets.

Buckets follow the existing usage-event retention and contain no prompt, response or key
content. Daily rollups retain their existing total-cost schema; per-bucket history is in
raw events. No billing, retention policy, live-provider metering or migration deployment
is performed here.
