# Managed automatic Chat stream preflight

Set `MULTILLM_STREAM_PREFLIGHT=strict` to validate the first useful output before
committing a managed automatic Chat stream. The default is `off`; absent or
unrecognized values also leave preflight disabled.

Only streaming `POST /v1/chat/completions` requests using an `auto:<route>` model
are eligible. Explicit provider models, provider/raw/native routes, other
protocol endpoints, nonstreaming requests, and roleplay keep their existing
behavior. The off path does not consume or wrap the response body.

## Validation and replay

The gate reads the existing client-facing Flask iterator, including any lazy
protocol translation. It never sends another upstream request. A complete Chat
SSE envelope containing nonempty text, reasoning (`reasoning_content`,
`reasoning`, or `thinking`), or streamed function/tool arguments unlocks the
stream. Role-only deltas, empty choices, empty content, tool names alone,
and heartbeat frames do not unlock it.

A successful response adds `X-MultiLLM-Stream-Preflight: validated`. Buffered
byte chunks are replayed once in their original order. Remaining chunks are
streamed unchanged. JSON is inspected, not serialized back into SSE. UTF-8,
JSON, LF, CRLF, and bare CR delimiters can span chunks; multiline data is
supported. Strict envelopes reject unexpected SSE fields and malformed Chat
choice/delta shapes.

The default limits are 65,536 inspected bytes and 32 complete nonempty SSE
frames. Heartbeats and metadata-only frames count toward the frame limit. A
useful event on the final permitted frame or byte passes. Only bytes inside
the byte allowance are inspected: when one source chunk crosses the limit, a
useful event before the limit still validates and the whole chunk is replayed;
without one the stream fails. Once validation succeeds, these lookahead limits
no longer apply.

The Python helper `preflight_chat_stream(response, *, max_bytes=65536,
max_events=32)` returns a `StreamPreflightResult` with the real downstream
`response`, a `validated` flag, and an `outcome`. Unsuccessful upstream HTTP
statuses return `skipped` and retain the existing dispatcher behavior.

## Failures and cleanup

Before useful output, failures return an actual JSON error response:

| Condition | HTTP status | `error.code` |
| --- | --- | --- |
| Empty terminal output, EOF, malformed SSE/JSON/UTF-8, non-SSE success body, or exhausted prefix limit | 502 | `upstream_stream_invalid` |
| Upstream read timeout | 504 | `upstream_stream_timeout` |
| In-band provider error or a typed lazy bridge failure | 502 | `upstream_stream_error` |

Provider error context is limited to redacted, length-bounded message, type,
and code strings in `error.provider_error`. Other provider fields and arbitrary
exception messages are not reflected. Failures never manufacture successful
assistant content.

A local preflight failure is terminal for that request. It does not grant
permission to retry or fail over: an invalid HTTP 200 stream does not establish
that the provider generated nothing. Route health records the validation
failure rather than success from the original HTTP status. Existing refusal
and transport failover rules remain in place for skipped responses.

The response owns cleanup through an idempotent closer shared by replay and
Flask close callbacks. It closes the original body and callbacks after normal
exhaustion, preflight failure, or downstream disconnect, including a response
closed before its replay iterator starts. Existing translated transports retain
their own idempotent upstream connection cleanup.

Late errors after validation remain stream errors. The gate relies on the
configured upstream read timeout. A blocked synchronous read cannot be
interrupted by a byte/event limit; there is no hard wall-clock deadline or
background reader thread. No body is persisted and no migration is needed.

## Deployment integration

Standalone Flask reads the variable directly. The Container deployment needs
`MULTILLM_STREAM_PREFLIGHT` added to the environment allowlist in
`worker/container-env.mjs` by the coordinator/W5 before activation.

README feature sentence for the coordinator/W5:

> Managed automatic Chat streams can opt into bounded first-event validation before commitment.

No new Worker test or package script registration is needed.
