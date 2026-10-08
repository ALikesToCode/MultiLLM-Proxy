# Partial usage and unknown cost

Managed request accounting keeps missing input and output counts separate from measured
zero. There is no new route, header or feature flag. This representation correction also
applies to routes forwarded by the Worker to Flask. Native edge accounting is unchanged.
Provider response bodies and streaming chunks pass through unchanged.

With the existing usage ledger enabled, a response containing
`{"usage":{"input_tokens":0}}` records `input_tokens: 0`, `output_tokens: null`.
If output tokens have a nonzero configured rate, `cost_usd` and `cost_basis` are null.
A response reporting both counts as zero records both as zero; a fully configured token
price then produces a measured zero cost. An unconfigured model still has null cost,
even when both measured counts are zero. A flat request price can be calculated without
token counts, and an explicitly zero token rate does not require that component's count.

Embedding usage has measured output tokens of zero. Accounting recognizes the
`/v1/embeddings` path or a response whose `data` items contain `embedding`. A response
with `prompt_tokens: 9` and no `completion_tokens` records input 9 and output 0, with
provider cost based only on input even when the model has a nonzero output rate.

With `USAGE_LEDGER_ENABLED=false`, accounting does not persist ledger rows. Response
bodies, admission checks and the existing budget behavior remain unchanged. This setting
does not disable budget checks or select a different interpretation of provider usage.
No new Container environment key is required.

## Observation and storage

`UsageObservation` carries optional counts, `basis` (`provider`, `estimated`, `unknown`)
and content-free provenance. Partial provider observations retain their known components.
Negative counts, booleans, strings and null are unknown independently; total tokens alone
do not identify input and output counts. JSON responses, nested Responses usage and
Anthropic message-start usage are supported. SSE observations merge each component's
latest valid count, including zero, across events and transport chunks.

An explicit `with_estimates` operation fills missing components and marks the result
`estimated`, retaining provider and request-estimate provenance. Accounting continues to
use the existing request estimate when no usage object is reported at all. Ledger rows
keep missing provider components null. For budget counting only, missing components are
filled from the request's existing input/output estimates; reported counts, including
zero, remain unchanged. For example, with input/output rates of $2/$8 per million and
request estimates of 100/200 tokens, measured input 9 with missing output counts
$0.001618 against the budget while the ledger cost and basis remain null.
Complete provider usage, complete estimates, cache hits and failures without usage retain existing accounting
and budget results. The cost service retains its legacy coercion for non-null invalid
estimate inputs; managed provider parsing validates counts before pricing.

The existing store accepts `cost_basis: "usage"`, `"estimate"` or null; these represent
internal provider, estimated and unknown cost respectively. No new fields or migration
are added. Internal provenance is not persisted. Existing cache-hit accounting retains
its `cache` basis; the current D1 validator does not accept that pre-existing value.
Changing that validator is outside this feature's ownership.

Recent usage records retain null counts and costs. Summary `cost_usd` is the sum of
priced requests; inspect `priced_requests` alongside `requests` for coverage. A summary
with zero priced requests does not establish that requests were free. Existing summaries
aggregate known token counts; they do not expose per-component coverage.

## Bounds and limitations

Non-streaming JSON observation is limited to 16 MiB. Streamed JSON uses the final 64 KiB
tail; usage outside that tail is unavailable. SSE keeps a bounded 64 KiB pending line and
one observation per request, so early token counts survive longer response bodies. SSE
usage must be single-line JSON; oversized or malformed lines are ignored. Closing an
aborted stream records only counts already observed, once, and releases its reservation.
No additional upstream request, retry or completion is generated.

Unknown cost is not an invoice and is not settled as measured spend. Existing budget
admission uses configured request estimates; priced partial usage counts conservatively
after settlement even when the ledger is disabled. That budget-only charge stays local
to the process and survives ledger flush/drop notifications and durable-total refreshes;
it is not stored as a measured cost and does not survive a process restart. Fully
unpriced models retain their current budget behavior. This feature does not introduce
durable budget holds, cache-token buckets or a provider billing reconciliation policy.
Operator pricing remains the cost
source; the feature does not verify live provider metering.

No prompt, output or credential content is added to accounting records or logs. Existing
ledger buffering, flush failure handling and raw/rollup retention settings still apply;
unknown rows have the same retention as priced rows. Tests use fake upstream responses
and isolated storage and do not certify deployment or native edge collection.
