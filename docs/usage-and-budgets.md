# Usage ledger, budgets and key controls

MultiLLM records every billable request in a durable usage ledger, and each proxy key
can carry a daily and monthly dollar budget, a model allowlist, an expiry time and a
list of client address ranges. Administrators set these on the Access page; everyone
can see their own usage on the Usage page and through `GET /v1/usage`.

## What is recorded

One ledger row per billable request: a `POST` to `/v1/chat/completions`,
`/optimize/v1/chat/completions`, `/intelligence/v1/chat/completions`, the free chat
routes, `/v1/responses`, `/v1/messages`, `/v1/images/generations`, `/v1/images/edits`,
`/v1/images/batch`, `/v1/videos`, `/v1/embeddings`, `/v1/audio/transcriptions`,
`/v1/audio/speech`, or a provider pass-through route such as
`/openai/v1/chat/completions`. Knowledge requests are excluded; they have their own
ledger. Reads such as `GET /v1/models` or video status polls are not recorded. A
request that omits `model` is checked and recorded as its route's default
(`auto:image-edit`, `auto:embed`, `auto:tts` or `auto:stt`).

An asynchronous batch (`POST /v1/images/batches`) is checked against the allowlist and
budget when it is submitted, but its items are recorded one row each, with endpoint
`/v1/images/batches`, when the Workflow runs them. Each item is checked again as it
runs, so a budget spent or an allowlist changed after submission fails the remaining
items with `budget_exceeded` or `model_not_allowed`. An answer served from the response
cache (`X-MultiLLM-Cache: hit`) is recorded with `cost_basis: "cache"` and no charge.

Each row holds the account name (`principal`), the key prefix (never the key), the
endpoint, the requested model, the selected `provider:model` (the candidate an
automatic or free route chose), the HTTP status, latency, token usage when the
provider reported it, the estimated cost in USD and how it was computed, the request
ID and the time. Prompts and outputs are never stored.

Token usage comes from the response body, including the final events of a streamed
response (send `stream_options.include_usage` to OpenAI-compatible providers to get
it). A streamed response is recorded when the stream closes, so its latency covers the
whole stream.

## Cost

Cost uses the operator's `MODEL_PRICING_USD_PER_MILLION` prices, never guessed
provider prices. An entry may add a flat `request` price in USD, charged once per
request, or per generated image on image routes, for media models that report no
tokens:

```env
MODEL_PRICING_USD_PER_MILLION='{"openai:*":{"input":2,"output":8},"gguu:*":{"request":0.04}}'
```

`cost_basis` is `usage` when the provider reported tokens and `estimate` when the
proxy's own token estimate was used. Requests to unpriced models and failed requests
(status 400 or above, with no usage reported) have no cost. Configured prices are
planning signals, not provider invoices.

## Storage

On Cloudflare the ledger lives in the `INTELLIGENCE_DB` D1 database (migration
`0007_usage_ledger.sql`), reached only through the Worker's private
`intelligence.internal/v1/usage` operations, so it survives Container sleep and
redeploys. Elsewhere it uses SQLite (`USAGE_DB_PATH`, default `instance/usage.sqlite3`),
or PostgreSQL when `CONTROL_PLANE_DATABASE_URL` is set. `USAGE_LEDGER_BACKEND` (`d1` or
`sql`) overrides the choice.

- `usage_events` holds raw rows and is pruned after `USAGE_LEDGER_RAW_RETENTION_DAYS`
  (30).
- `usage_daily` holds per-day, per-key, per-model totals: requests, errors, tokens,
  cost, priced requests and a latency histogram. It is kept for
  `USAGE_LEDGER_ROLLUP_RETENTION_DAYS` (400). The usage page, `/v1/usage` and budgets
  read these totals. p50 and p95 latency are estimated from the histogram buckets
  (250 ms up to 120 s), so they are exact to the bucket, interpolated inside it.
- `usage_batches` records applied flush batches so a retried flush is stored once.

### Why D1 and not Workers Analytics Engine

Analytics Engine fits high-volume event analytics, but not a ledger that enforces
budgets. Its data points are limited to 20 blobs, 20 doubles and one index; a Worker
invocation can write at most 250 of them; data is kept for three months; high-volume
indexes are sampled, so totals must be weighted by `_sample_interval`; and it is read
only through the account-level SQL API with an API token, not through a binding.
Budgets need exact totals that the Container can read on demand, with longer history
for monthly and dashboard views. D1 provides that with fixed, transactional
statements behind the private handler. Each flush writes the whole batch in one
statement per table by passing the rows as a single JSON parameter, which stays well
inside D1's limit of 100 bound parameters per query and its per-invocation query
limits.

If you want Analytics Engine for ad-hoc analysis anyway, bind a dataset as
`USAGE_ANALYTICS` in `wrangler.jsonc`. The Worker then mirrors each stored row (index:
account; blobs: route kind, endpoint, requested and selected model, cost basis;
doubles: status, latency, input and output tokens, cost). D1 stays the record.

### Write-behind batching

Requests never wait on the ledger. A row goes into a bounded in-memory buffer
(`USAGE_LEDGER_MAX_BUFFER`, 10000 rows). A background thread flushes up to
`USAGE_LEDGER_BATCH_SIZE` (200) rows every `USAGE_LEDGER_FLUSH_SECONDS` (5), sooner when
a batch fills, and again at process exit (up to `USAGE_LEDGER_SHUTDOWN_SECONDS`, 5). A
failed flush keeps its batch and retries it with backoff under the same batch ID;
after `USAGE_LEDGER_MAX_ATTEMPTS` (12) failures the batch is dropped. A full buffer
drops the newest row. Dropped rows are counted and logged; administrators see the
counters (`buffered`, `recorded`, `dropped`, `failed_flushes`) on the Usage page. Rows
still in the buffer appear in the totals a few seconds later. Raw rows and old totals
are pruned hourly (`USAGE_LEDGER_PRUNE_INTERVAL_SECONDS`).

Rows still buffered when a Container is killed without a graceful shutdown are lost;
that, and dropped rows, are the only gaps.

## Budgets

A key may have a daily and a monthly limit in USD. Either may be empty (no limit); `0`
freezes the key. Periods are UTC days and calendar months. Administrator keys have no
budget unless one is set explicitly.

Before dispatch the proxy estimates the request's cost from the prompt-token estimate,
the requested output limit (1024 tokens when none is given) and the image count. For
an automatic route it uses the most expensive priced candidate. The request is
admitted only if the ledger total for the period, plus what this process recorded
since it last read that total, plus the estimates of the key's requests still in
flight, plus this estimate fits every limit. When the request finishes, its estimate is
released and its settled cost counts instead. Totals are read from `usage_daily` at
most every `USAGE_BUDGET_REFRESH_SECONDS` (60) per key, and immediately after the UTC
day changes, so several Containers sharing D1 converge within that interval.

A refused request gets:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 7201

{"error": "budget_exceeded",
 "message": "This key's daily budget of $5.00 is spent ($4.9950 used or in flight, this request is estimated at $0.0120). It resets at 2026-09-27T00:00:00+00:00.",
 "budget": {"period": "daily", "limit_usd": 5.0, "spent_usd": 4.995, "in_flight_usd": 0.0,
            "estimate_usd": 0.012, "resets_at": "2026-09-27T00:00:00+00:00"}}
```

`Retry-After` counts the seconds to the reset of the exceeded period (the later one
when both are exceeded). If a budgeted key's totals cannot be read at all yet (for
example D1 is unavailable right after a restart), its requests get 503
`budget_unavailable` with `Retry-After: 5`; once a total has been read, a later read
failure keeps using it.

Only priced requests count, so price every model a budgeted key may use. Combine a
budget with a model allowlist to keep a key on priced models.

## Model allowlists

A key may list allowed model IDs or patterns, where `*` matches any characters:
`auto:*`, `free:*`, `openai:gpt-4.1`, `gguu:*`. Matching ignores case. The requested
model is checked before dispatch on chat, responses, images (every item of a batch;
items without a model use `auto:image`), videos (`auto:video` by default), embeddings,
audio and provider pass-through routes, where the model is `provider:<body model>`. A
pass-through request that names no model needs `provider:*` or `*`. An automatic route
is allowed by its own ID; its candidates are the operator's choice. A refused request
gets 403 `model_not_allowed`. `GET /v1/models` lists only the models the key may use.

## Expiry and client addresses

`expires_at` ends a key at a UTC time: API requests get 401 `key_expired`, the key can
no longer sign in to the dashboard, and existing dashboard sessions end.

`allowed_ips` is a list of IP addresses or CIDR ranges (IPv4 and IPv6). Requests from
other addresses get 403 `ip_not_allowed`. The client address is Cloudflare's
`CF-Connecting-IP` when `MULTILLM_TRUST_PROXY_HEADERS` is set (the Worker sets it for
the Container; clients cannot set that header through Cloudflare), and otherwise the
connection's peer address. Address ranges apply to API keys, not dashboard sessions.

The Worker's Knowledge edge, which verifies D1 accounts itself, never serves an expired
key or one used outside its address ranges; it passes such a request to the Container,
which answers with the error above.
The environment-managed admin (`ADMIN_USERNAME` with `ADMIN_API_KEY`) is the
break-glass credential: it cannot be given an expiry or address ranges, only budgets
and a model allowlist.

## Setting controls

On the Access page, **Limits** opens a form for an account's budgets, allowed models,
client addresses and expiry. The account list shows a summary of each key's limits.
Rotating a key keeps its limits. The same change through the API, from an
administrator's dashboard session with its CSRF token:

```http
PUT /users/docs-agent/controls
Content-Type: application/json

{"daily_budget_usd": 5, "monthly_budget_usd": 50, "allowed_models": ["auto:*", "free:*"],
 "allowed_ips": ["203.0.113.0/24"], "expires_at": "2026-12-31T00:00:00Z"}
```

The body replaces all five controls; send `null` or an empty list to clear one.
Invalid values get 400 with a message naming the field. The controls are stored on
the account (the `control_users` D1 table, or the `users` table in SQLite and
PostgreSQL) and are included in encrypted control-plane backups.

## Usage page

**Usage** in the dashboard shows totals, a per-day table (requests, errors, cost, p50
and p95 latency) and a per-model table for the last 7, 30 or 90 days. Administrators
can view all keys, pick one key (which also shows its budget and controls), and see a
per-key table. Operators see only their own key.

## `GET /v1/usage`

Agents can read their own usage and remaining budget with any key that has the
`models` scope. `models` was chosen over a new scope because every standard key already
holds it, the response covers only the caller's own account, and adding a scope would
break existing keys until each one was updated.

```bash
curl -s https://proxy.example/v1/usage?days=7 -H "Authorization: Bearer $MULTILLM_API_KEY"
```

```json
{
  "object": "usage",
  "principal": "docs-agent",
  "key_prefix": "mllm_AbCdEfGh",
  "budget": {
    "totals_available": true, "day": "2026-09-26", "month": "2026-09",
    "spent_today_usd": 1.24, "spent_this_month_usd": 18.9, "in_flight_usd": 0.01,
    "daily_budget_usd": 5.0, "monthly_budget_usd": 50.0,
    "daily_remaining_usd": 3.75, "monthly_remaining_usd": 31.09,
    "daily_resets_at": "2026-09-27T00:00:00+00:00", "monthly_resets_at": "2026-10-01T00:00:00+00:00"
  },
  "controls": {"allowed_models": ["auto:*", "free:*"], "allowed_ips": null, "expires_at": null},
  "range": {"since": "2026-09-20", "until": "2026-09-26", "days": 7},
  "history_available": true,
  "totals": {"requests": 412, "errors": 3, "cost_usd": 6.12, "latency_p50_ms": 840, "latency_p95_ms": 4200, "...": "..."},
  "daily": [{"day": "2026-09-26", "requests": 60, "errors": 0, "cost_usd": 1.24, "latency_p50_ms": 790, "latency_p95_ms": 3900, "...": "..."}],
  "models": [{"model": "openai:gpt-4.1", "requests": 300, "cost_usd": 5.8, "...": "..."}]
}
```

`days` accepts 1 to 90 (default 30). Daily rows also carry `input_tokens`,
`output_tokens`, `priced_requests`, `error_rate` and `latency_avg_ms`. When the ledger
cannot be read, `history_available` is false and the budget figures come from what the
process knows.

## Request metrics after a restart

The Operations dashboard keeps recent requests in memory. At startup the proxy loads
the last day of ledger rows (up to `USAGE_METRICS_HYDRATE_ROWS`, 2000) written before
the process started, in the background, so request counts, failures and the request
log survive a Container restart. Non-billable requests are not in the ledger and start
from zero.

## Telemetry export (optional)

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export a span per billable request and delta
metrics over OTLP/HTTP with JSON encoding. Signals go to `<endpoint>/v1/traces` and
`<endpoint>/v1/metrics`; `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` and
`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` override one signal each.
`OTEL_EXPORTER_OTLP_HEADERS` takes `key=value` pairs separated by commas, with
percent-encoded values (for a collector's authentication header). `OTEL_SERVICE_NAME`
defaults to `multillm-proxy`.

Spans carry the route kind, method, path, status, requested and selected model, token
counts, estimated cost, account name and request ID, and continue a caller's W3C
`traceparent`. Metrics are `multillm.requests`, `multillm.cost` and `multillm.tokens`,
by route kind, model and status class. Prompts, outputs, keys and key prefixes are
never exported. Export runs in a background thread with a bounded queue of 2048
records; when the collector is slow or down, records are dropped and counted, and
serving is unaffected. No OpenTelemetry package is required.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `USAGE_LEDGER_ENABLED` | `true` | Record billable requests. Budgets then count only this process's requests. |
| `USAGE_LEDGER_BACKEND` | D1 when available, else `sql` | `d1` or `sql`. |
| `USAGE_DB_PATH` | `instance/usage.sqlite3` | SQLite file for the `sql` backend. |
| `USAGE_LEDGER_FLUSH_SECONDS` | `5` | Flush interval. |
| `USAGE_LEDGER_BATCH_SIZE` | `200` | Rows per flush (at most 500). |
| `USAGE_LEDGER_MAX_BUFFER` | `10000` | Buffered rows before new ones are dropped. |
| `USAGE_LEDGER_MAX_ATTEMPTS` | `12` | Failed flushes before a batch is dropped. |
| `USAGE_LEDGER_RAW_RETENTION_DAYS` | `30` | Days of raw rows. |
| `USAGE_LEDGER_ROLLUP_RETENTION_DAYS` | `400` | Days of daily totals. |
| `USAGE_LEDGER_PRUNE_INTERVAL_SECONDS` | `3600` | How often to prune. |
| `USAGE_LEDGER_SHUTDOWN_SECONDS` | `5` | Flush time at process exit. |
| `USAGE_METRICS_HYDRATE_ROWS` | `2000` | Ledger rows loaded into the dashboard at startup. |
| `USAGE_BUDGET_REFRESH_SECONDS` | `60` | How often a budgeted key's durable totals are re-read. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Enables OTLP export. |

## Deploying

1. Apply D1 migration `0007_usage_ledger.sql` (`npx wrangler d1 migrations apply
   multillm-intelligence --remote`, or `npm run deploy`, which applies pending migrations
   first). A plain `wrangler deploy` does not apply migrations. Code deployed before the
   migration keeps authenticating accounts: account reads fall back to the older columns
   with no controls, saving a key's controls fails with 503, ledger flushes fail and are
   retried, and `/ready` reports the missing usage tables.
2. Set `MODEL_PRICING_USD_PER_MILLION` for the models budgeted keys use; the Worker
   passes it to the Container.
3. Optionally bind an Analytics Engine dataset as `USAGE_ANALYTICS`, and set the
   `OTEL_*` variables to export telemetry.
