# Native edge request metrics

`NATIVE_EDGE_METRICS_ENABLED` defaults to false. Unset, empty and `false` values preserve
existing native responses, headers, streams, ledger writes and logs. Metrics hooks
stay off; other collaborators use their own flags. Set the Worker variable to `true` to enable observation; values are trimmed and
case-insensitive. A malformed setting disables the feature and emits one content-free
warning per isolate. For example:

```json
{"NATIVE_EDGE_METRICS_ENABLED": "true", "PROMETHEUS_ENABLED": "true"}
```

To disable it:

```json
{"NATIVE_EDGE_METRICS_ENABLED": "false"}
```

## Scope and identity

After existing route authentication, native Codex Easy, LinkAPI and edge OpenCode
POST generations are observed. Kimi generations and non-edge OpenCode currently go
through the Container and retain Flask ledger ownership. Models, health, token-count,
Knowledge and roleplay paths retain their existing accounting. No retry is introduced.

Each native attempt gets a generated request ID and a SHA-256 digest of the verified
native admin identity with an `edge:` namespace. Client identity and request-ID headers
cannot supply these values. This identity is separate from the Flask username principal;
reports and budgets must not assume the two namespaces are combined. Selected models
come from the authenticated request, never an upstream response's model field. The
native admin route currently has no narrower per-model grant. A request model that is
missing, malformed or outside the parse bound remains unknown.

Enabled Container forwarding strips client copies of edge principal, request ID and
ledger-owner headers and generates `x-request-id`. Flask still authenticates the caller
and owns its usage row. Edge forwarding never writes a second row.

## Usage, failures and cost

The observer accepts OpenAI Chat/Responses and Anthropic usage envelopes, retaining
input and output counts independently. Zero is measured zero; missing, malformed or
negative components remain null. Split SSE events merge the latest valid component.
Complete measured usage on a completed successful response has basis `measured`;
partial, usage-less, canceled, failed and incomplete attempts have basis `unknown`.
No token estimates are invented. The observer accepts a code-supplied `usageEstimate`
collaborator value, fills only missing components and marks those observations
`estimated`. Measured zero is preserved. Usage-less and canceled attempts stay unknown
even with estimates. The registered native routes supply no estimates by default.

Costs use `MODEL_PRICING_USD_PER_MILLION` with explicit input/output prices, optional
per-request prices, provider wildcards and the global wildcard. Costs remain null without
complete successful usage and valid prices. They are configured estimates, not invoices.
Known configured costs map to the existing D1 `usage` basis; unknown costs map to null.
Prompt-cache usage buckets are not priced separately.

Native downstream HTTP status, headers and bytes are unchanged. Ledger-only status 499
means cancellation, 502 means a transport or in-stream error, and 520 means incomplete
or unknown usage on an otherwise successful HTTP response. Upstream HTTP errors keep
their status. These classifications prevent unknown attempts from becoming successes
in daily rollups. Partial counts remain useful without treating missing cost as free.

## Operational bounds and retention

Response observation uses one pull-driven reader with no response clone, tee or
full-body queue. SSE line/event carry and non-stream JSON observation are bounded at
64 KiB. Oversized events are discarded for accounting and bytes are still forwarded.
Parsing recovers at subsequent event boundaries. JSON responses above the bound have
unknown usage. Authenticated request-model extraction also reads at most 64 KiB of a
request clone; its reader is canceled afterwards. First-token latency is recorded only
for recognizable streaming content, reasoning or tool deltas; it stays unknown for
non-stream responses. Duration uses a monotonic clock, includes dispatch, and is clamped
to the ledger's 24-hour bound. A terminal SSE marker and complete usage are required
for successful stream accounting.

Cancellation and body/fetch failures finalize once. Finalization uses `ctx.waitUntil`
when available; missing/broken D1 emits fixed content-free errors and never replaces
the native result. This is best-effort telemetry, not a billing guarantee. No prompt,
tool arguments, output, raw key, exception detail or key prefix is persisted or logged
by this feature. The existing `usage_events`, `usage_daily` and `usage_batches` schema
and pruning policy apply; there is no new retention store or migration. Request IDs
and model identity are durable; TTFT and richer outcomes are not additional D1 columns.

With both flags enabled, the existing authenticated `/v1/metrics/prometheus` endpoint
appends native counters using the existing exporter's content type and label escaping. Authentication
errors and non-Prometheus responses pass through unchanged. The public status endpoint
is unchanged. Labels contain only four fixed provider names and five fixed outcomes:
at most 120 series, with no principal, request ID, model or content labels. Counters
track requests, duration, observed TTFT and its coverage, measured usage coverage and
priced coverage. Counters are isolate-local and reset when the isolate restarts; a
scrape does not aggregate other isolates. D1 remains the durable count source.

## Static lifecycle integration

`createGatewayLifecycle` exposes `authorize`, `admit`, `before_dispatch`, `observe` and
`finalize` in registration order with one finalizer per request. Hook context contains
only content-free metadata. Native dispatch accepts code-supplied named collaborators;
there is no dynamic import, executable configuration or discovery. Finalization tries
every collaborator even if one fails, then reports the failure without changing response
bytes. Other gateway features attach to native dispatch as code-registered
collaborators on these hooks.

Native registration checks revision security freshness before resolving the immutable
retention policy, acquiring admission and dispatching. Retention uses the authenticated
bootstrap username and key digest with the public route, ignoring caller identity headers.
Admission shares the Flask username digest and provider-prefixed model group; forwarded
requests acquire only in Flask. Native metrics keep their separate ledger principal.
Collaborators declare a code-supplied `enabled(env)` predicate or `flag` name. Existing
metrics collaborators without a gate retain the metrics flag. No configuration can
supply executable hooks.

Native cancellation cleanup always runs, even with the opt-in flags off. Request abort
reaches provider fetch and its body owner; admission loss closes the same owner.
Cancellation outcomes accompany finalization, and admission releases once. Revision
polling runs through scheduled work and native request background work. Strict native
security installers read all account pages with every control column and validate model
overrides; authority failures cannot certify freshness. Bootstrap admin authentication
continues to use its environment key. Native routes do not consume automatic routes or
provider catalog copies, so those ordinary domains have no native installer. With all
opt-in flags off, normal bytes, headers, storage writes and logs remain unchanged.
