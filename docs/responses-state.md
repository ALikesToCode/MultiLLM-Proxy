# Hosted Responses continuation

`HOSTED_RESPONSES_ENABLED` enables principal-owned continuation on the managed
`POST /v1/responses` route. It defaults to off; an empty or malformed value is
off. A malformed value produces one warning without the supplied value. When
off, existing provider requests, response bytes, headers and storage behavior
are preserved, and retrieval and deletion retain their existing routing behavior.

Enable the flag in the Worker and Flask Container, select the existing D1
intelligence storage backend, and apply the additive `hosted_responses` migration.
The authority requires `INTELLIGENCE_DB` and the existing `multillm_media` R2
bucket. Missing bindings or a missing table produce a JSON 503 before provider
dispatch for a hosted request. Native Worker generation routes do not serve
hosted Responses; managed requests are forwarded to Flask.

## Requests

This body opts into gateway storage:

```json
{"model":"provider:model","input":"Summarize this text","store":true,"gateway_state":true}
```

A classified completed response returns an ID beginning with the reserved
gateway prefix `gwresp_`, followed by 32 hexadecimal characters. The gateway
removes `gateway_state` before dispatch and disables provider-side storage for
the opted-in generation. The returned response has `store: true`.

Continue using that ID and a new input, including tool results:

```json
{"model":"provider:model","previous_response_id":"gwresp_0123456789abcdef0123456789abcdef","input":[{"type":"function_call_output","call_id":"call_1","output":"result"}],"store":true,"gateway_state":true}
```

The gateway rebuilds the original input, completed output items and new input
in that order. It preserves item order and tool call/result boundaries. Each
stored child is self-contained and has its own expiry. A gateway parent can
also be used without `gateway_state: true`; the generation then uses the
retained context and does not create another hosted record.

Without hosted opt-in or a gateway parent, requests keep the existing behavior.
For example, `{"store":true,"previous_response_id":"resp_provider",...}`
continues through the provider unchanged. Combining hosted opt-in with a
provider-owned parent returns 400: supply full input or use a gateway parent,
because the gateway cannot retain unseen provider history. Hosted opt-in
requires the literal boolean `store: true`.

## Retrieval and deletion

Authenticated `GET /v1/responses/<id>` returns the stored completed response.
Authenticated `DELETE /v1/responses/<id>` removes its metadata and R2 body and
returns `{"id":"gwresp_...","object":"response.deleted","deleted":true}`.
Both operations accept only gateway IDs owned by the authenticated principal.
An absent, expired, malformed or foreign ID returns JSON 404. A foreign ID does
not reveal content or authorize deletion. Responses use `Cache-Control: no-store`.

Deletion is explicit. TTL expiry is the only automatic deletion condition;
expired records are removed when accessed. Failed deletions retain an
inaccessible metadata marker so a subsequent explicit DELETE can finish.
Missing or corrupt bodies return 503 without regeneration or automatic repair.

## Completion, limits and cost

State is published only after completed terminal status and settled existing
usage accounting, with measured or explicitly unknown usage. Failed,
incomplete, cancelled, deadline-expired and ambiguous outcomes cannot be read
or continued as completed state. Existing conservative accounting decisions
remain authoritative, including uncertain streaming handoffs under a deadline.
An unverified completed outcome returns `response_outcome_unknown` without
submitting the generation again. Storage acknowledgement lost after dispatch
also does not grant permission to repeat a provider call.

Streaming stores after a terminal `response.completed` event, clean EOF and
accounting settlement. The terminal event is held until storage succeeds.
An interrupted stream has no completed hosted state; errors are returned as
SSE error events once streaming has begun. There is no SSE reattachment.
Enabled managed idempotency can replay a completed nonstreaming response with
the same gateway ID; an unknown earlier outcome remains blocked. Streaming
idempotency replay is unsupported.

Each stored input plus response is limited to 1 MiB of UTF-8 JSON, expires
24 hours after creation, and belongs to a chain of at most 16 generations.
Oversized input and excessive depth return 400 before dispatch. An oversized
generated state returns 502 after dispatch and still incurs provider usage.
Storage errors return 503 and never trigger a provider retry. D1 stores owner,
status, provider/model, parent, policy revision, expiry, body pointer, byte
length and SHA-256; R2 bodies use the `responses-state/` prefix. The bounded
private hop is `POST http://intelligence.internal/v1/managed-state/responses`.

Zero-content retention, including request-local retention from PII redaction,
returns 400 `retention_conflict` before dispatch for
hosted opt-in and gateway continuation. It also forbids retrieval; explicit
deletion remains available. Hosted storage introduces D1/R2 storage operations
in addition to existing provider costs. No prompt or response content is logged.
