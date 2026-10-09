# Generation deadlines

Send `X-MultiLLM-Deadline-Ms` to set a relative budget for one generation. The
header accepts an integer from 1 to `GENERATION_DEADLINE_MAX_MS` (300000 by
default). Setup, token counting, admission, allowed retry waits, provider calls,
stream preflight and body reads all consume that same budget. A shorter key or
route limit takes precedence.

Without the header, existing timeouts, retries, response bytes and stream behavior
remain unchanged. An empty `GENERATION_DEADLINE_MAX_MS` uses the default. A
malformed maximum disables deadlines and logs one warning without its value.
A malformed request header returns HTTP 400 `invalid_generation_deadline`.

For example, this request has a ten-second generation budget:

```sh
curl "$GATEWAY_URL/v1/chat/completions" \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'X-MultiLLM-Deadline-Ms: 10000' \
  -d '{"model":"openai:gpt-4.1","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

Omit the deadline header to use the existing timeouts:

```sh
curl "$GATEWAY_URL/v1/chat/completions" \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"openai:gpt-4.1","messages":[{"role":"user","content":"Hello"}]}'
```

Before response commitment, expiry returns HTTP 504 with an error whose code is
`generation_deadline_exceeded`. After an SSE stream is committed, expiry emits
an error event in the selected Chat, Responses or Messages protocol and cancels
the upstream. It does not append a stop event or `[DONE]`, or start a fallback.
Binary streams terminate with a transport error because they have no SSE error
envelope. Chat SSE preflight uses the existing 65536-byte/32-event validation
bounds. Other SSE prefixes inspect at most 65536 bytes before commitment;
transport reads can deliver a larger chunk containing that prefix.
Exhausting the prefix bound or reaching EOF before useful output returns a real
HTTP 502 `upstream_stream_invalid` error and does not authorize replay.

The budget uses each host's monotonic clock. Forwarding sends only the rounded-down
remaining milliseconds in `X-MultiLLM-Internal-Deadline-Ms`. The forwarding
boundary strips any caller-supplied internal budget. The receiving Flask boundary
accepts that header only after its fixed transport verifier authenticates the
internal hop; public API authentication alone is not proof of an internal hop.
No monotonic timestamp is transmitted or compared across machines.

The deadline limits waiting and requests local cancellation. It cannot guarantee
that a provider stops computation or billing. Synchronous CPU setup cannot be
preempted; it is checked before further dispatch. Flask transport connects and
reads use bounded timeouts, and the cancellation owner closes a handed-off
response at expiry. A timeout before upstream handoff relies on the transport's
connect/read timeout rather than a separate socket owner.

Cancellation never grants replay permission. A handoff without confirmed final
usage remains ambiguous, even after clean EOF. Finalizers use
`settlement_information` (Flask) or `settlementInformation` (Worker) to retain
unknown usage and reservation information for settlement. Deadlines do not
create a durable reservation store or estimate a successful charge. They store
no prompt or response content and do not change the request's retention policy.
