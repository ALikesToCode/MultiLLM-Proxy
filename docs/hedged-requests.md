# Bounded hedged auto requests

Hedging can race the first two candidates of a managed auto route for a pure,
non-streaming `POST /v1/chat/completions` request. The second candidate starts
after a delay if the first has not returned a useful, complete response. The
first validated response wins. There are at most two attempts in total.

## Configuration

Hedging is off by default. Disabling it keeps the existing auto-route response,
headers, accounting and storage behavior:

```text
HEDGED_REQUESTS_ENABLED=false
HEDGED_REQUESTS_POLICY_JSON={}
```

Enable only routes whose providers support duplicate-safe generation or whose
pure-generation duplication contract has been reviewed. `idempotent_safe` is
an operator assertion; a request key alone does not establish provider safety.

```text
HEDGED_REQUESTS_ENABLED=true
HEDGED_REQUESTS_POLICY_JSON={"auto:fast":{"enabled":true,"delay_ms":150,"max_duplicates":2,"idempotent_safe":true}}
MANAGED_IDEMPOTENCY_ENABLED=true
USAGE_RESERVATIONS_ENABLED=true
```

Configure the existing managed idempotency and reservation authorities, caller
budget caps, candidate pricing, and shared admission capacity as described in
[managed idempotency](managed-idempotency.md),
[usage reservations](usage-reservations.md) and
[admission leases](admission-leases.md). The Flask Container must receive both
`HEDGED_REQUESTS_ENABLED` and `HEDGED_REQUESTS_POLICY_JSON` when used behind the
Worker. This feature uses managed Flask dispatch; native Worker provider calls
and raw passthrough routes keep their existing behavior.

Each policy may contain only `enabled`, `delay_ms`, `max_duplicates` and
`idempotent_safe`. Flags must be JSON booleans. The delay must be an integer
from 1 through 1000 milliseconds; its default is 150. `max_duplicates` must be
the integer 2, meaning the original plus one duplicate. Both flags default to
false. Unknown fields, duplicate fields, invalid route names or an invalid
entry disable the whole policy map. Empty settings use the defaults. Invalid
settings produce one warning per setting without logging its value.

## Eligible requests

An enabled route must have `idempotent_safe: true`. Send a stable
`Idempotency-Key` through managed idempotency, with usage reservations enabled,
known prices and enough caller budget for both conservative costs:

```http
POST /v1/chat/completions
Content-Type: application/json
Idempotency-Key: generation-123

{"model":"auto:fast","messages":[{"role":"user","content":"Summarize this text."}],"max_tokens":256}
```

The request must specify a positive integer `max_tokens` or
`max_completion_tokens` so both output costs can be bounded. It must request
one completion, omit `tools`, `tool_choice`, `functions` and `function_call`
entirely, and omit streaming. Tool repair and context paging also keep the
existing single-call path. Without these requirements, a caller cap or an
active managed idempotency claim, the existing route loop handles the request.

An otherwise eligible enabled policy with an unknown candidate price returns
HTTP 503 with `unpriced_reservation`. If both holds cannot fit the caller's
caps, the existing single-call path applies its normal budget policy. A durable
reservation or dispatch-boundary failure prevents submission and returns 503.

## Timing, completion and cleanup

Both conservative holds exist before the first submission. The duplicate starts
only after the configured delay from the first submission, while the shared
generation deadline has room and a second admission lease is immediately
available. Admission acquisition is attempted once; there is no queue or retry.
A denied lease, exhausted deadline window or completed first response suppresses
the duplicate and releases its unused hold.

Latency admission restricts candidates before the race. Each opted-in attempt has its own canary annotation and scanner; inspection precedes winner validation and settlement. Cancelled losers do not update successful latency observations or learned cooldowns.

The winner must have HTTP 200, a valid complete JSON envelope, useful content in
every choice, and no tool or function calls. Validation buffers at most 1 MiB.
Empty, truncated or incomplete responses cannot win; a successful HTTP status
without valid completion becomes a 502 error if neither candidate succeeds.
Provider errors retain their normal error response. Caller cancellation and the
shared deadline stop both attempts through the existing cancellation transport.

Each race uses at most two request-local threads. Cleanup joins the started
threads, closes cancelled transports through their existing cancellation owner,
and releases admission leases. A transport blocked before a closable response is
available must return within its configured timeout; Python threads cannot
forcibly interrupt arbitrary blocking provider code. No third candidate or new
provider retry is permitted after entering the race.

## Cost and retention

Every dispatched attempt has its own durable reservation and accounting row.
Measured usage settles both candidates, including the loser. An unknown outcome
retains its hold for the existing reservation review and reconciliation process;
cancelling a request does not prove that the provider avoided billing. A duplicate
that never dispatched releases its hold without recording provider usage.

Managed idempotency owns the caller's response. A successful race can replay
only when the existing retention policy permits response content. Failed or
ambiguous races remain blocked under that policy rather than granting another
generation. Existing zero-content retention rules still apply. Hedging adds no
prompt or response logs, schema migration, public route or response header; the
existing auto-route headers identify the selected model and attempt count.
