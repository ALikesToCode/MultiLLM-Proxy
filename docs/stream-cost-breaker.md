# Stream cost breaker

The stream cost breaker is off by default. Set `STREAM_COST_BREAKER_ENABLED=true`
and set a key's `max_stream_cost_usd` through its existing administrator controls
endpoint to enforce a cap. Empty or malformed flags disable enforcement; malformed
flags produce one warning without their value.

Disabled examples:

```json
{"max_stream_cost_usd": null}
```

With the flag off, existing streams, account queries, writes and public key records
keep their original shape. With a null cap, the body and public key record are
unchanged. Existing keys remain disabled after migration. Clearing a cap uses an
explicit null; omitting it during an account update or key rotation preserves it.

Enabled example (five cents):

```json
{"max_stream_cost_usd": 0.05}
```

Caps use integer micro-USD in storage. Values must be nonnegative, finite, no more
than 1,000,000 USD, and exactly representable in whole micro-USD. Zero is a valid
cap. Apply `intelligence-migrations/0030_stream_cost_caps.sql` to D1 before enabling
the flag. It adds a nullable `control_users.max_stream_cost_microusd` column.
The local SQL account store adds its corresponding nullable column when enabled.
Enabled D1 account reads and writes return HTTP 503
`stream_cost_storage_unavailable` if the column is missing, without dropping
controls or falling back to another store.

## Prices and running cost

Configure the existing `MODEL_PRICING_USD_PER_MILLION` catalog with provider-qualified
models and input, cache-read, cache-write and output prices. Existing
`PROMPT_CACHE_PRICE_METADATA_JSON` can supplement missing cache prices.
For example:

```json
{"openai:example-model": {"input": 2, "cache_read": 0.5, "cache_write": 3, "output": 8}}
```

All eligible automatic-route candidates must have a known bound. Missing pricing
returns HTTP 503 `stream_cost_unpriced` before provider handoff. An input estimate
already above the cap returns HTTP 429 `stream_cost_cap_exceeded`. These checks
never grant retry permission.

Provider usage uses the existing inclusive OpenAI and exclusive Anthropic cache
bucket conventions. Complete usable observations are labeled `measured`.
Otherwise, `conservative_estimate` uses the highest configured input/cache rate
and a byte-count bound for input structures and emitted deltas. Tool arguments,
reasoning and text all contribute. Each UTF-8 byte is treated as an output token
when a tokenizer or provider count is unavailable. This deliberately overestimates
ordinary text. Input framing, hidden reasoning, multimedia and provider-added
structures can exceed this estimate; the cap is an observation threshold, not an
invoice ceiling. Pricing is captured for each breaker before streaming.

## Stream errors and cleanup

The breaker buffers complete SSE frames across socket reads and UTF-8 boundaries.
It checks each frame before emitting it and withholds terminal success frames until
the trailer is checked. Frames and the terminal trailer are each limited to
64 KiB, plus the current upstream read. A malformed, incomplete or oversized
frame fails closed with the protocol's error envelope.

Managed canary inspection runs before cost inspection. If either stops the stream, the client receives one protocol error, upstream cancellation runs once, and unknown spend retains its ambiguous hold.

A crossing stops upstream consumption and closes its owner once:

- Chat emits `data: {"error":{"code":"stream_cost_cap_exceeded", ...}}`.
- Anthropic emits `event: error` with an error object.
- Responses emits `event: response.failed` with a failed response object.

A rejected stream never emits a fabricated stop reason or successful `[DONE]`.
After headers are sent, the HTTP status can remain 200; clients must inspect the
SSE error event. Ledger finalization records an aborted or unresolved stream as
499. Error fields and logs contain no prompt, output, key, cap value or provider
error text. Raw streams bypass the wrapper when enforcement is disabled.

Upstream read buffering is at most 64 KiB in the shared HTTP transport, but a
provider can generate or queue more work before cancellation reaches it. Native
Worker buffering also includes the current provider read. No bound on the
provider's undisclosed queued work or invoice overshoot is promised.

## Usage holds and retention

Without final complete provider usage, do not settle a reservation as measured.
Existing durable usage reservations retain the conservative hold in the
`unknown` state for reconciliation; they are not released by stream cleanup.
Enable `USAGE_RESERVATIONS_ENABLED` for durable monetary holds. Legacy process
reservations remain held while the process retains them, but cannot survive a
restart and retain their existing review/expiry behavior. A key with no daily or
monthly budget has no pre-existing monetary reservation.

The breaker retains only bounded parsing buffers during a request and content-free
cost/usage state afterward. It does not persist prompt or response content.
Existing retention and ledger policies continue to apply.

## Native Worker interface

Before dispatch, call `prepareStreamCostBreaker(env, user, models, inputTokens,
protocol)` with all eligible provider-qualified models and a conservative input
token bound. It returns null for disabled keys and throws errors with
`status` and `code` on failed admission.

After upstream dispatch, wrap the SSE body with `wrapStreamCost(body, state,
{abort, onFinal})`. Pass the upstream abort callback and an accounting finalizer.
The finalizer receives `finalUsage`, `runningMicrousd`, `basis` and `exceeded`;
retain the existing hold when `finalUsage` is null. Supply the environment to
`activeUsersByPrefix(db, prefix, env)` when authenticating native streams so
the cap column is read and schema errors fail closed.
