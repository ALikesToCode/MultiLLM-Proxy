# Tool-call reliability layer

Function tools are validated against caller-declared schemas at the Container's
OpenAI Chat pivot. The Worker forwards the request and exposes the repair header;
it does not parse model output. No new dependencies, bindings, migrations, or
provider credentials are required.

## Public contract

`services/tool_call_repair.py` exports:

- `validate_arguments(schema, value) -> list[str]`
- `repair_tool_calls(message, tools, *, tool_choice=None, mode="repair", allow_extraction=True) -> (message, report)`

The report contains integer `checked`, `repaired`, `invalid`, and `extracted`
counts, plus `fixes: [{index, fixes: [...]}]` and `errors: [{index, errors: [...]}]`.
Invalid calls are retained unchanged; input objects are never mutated. Request
orchestration adds `reasked` to its report. Completion choices carry
`finish_reason: "tool_calls"` after extraction, rather than adding that field to
the assistant message.

## Deterministic repair

Arguments must resolve to an object. Strict valid JSON is preserved verbatim.
The parser rejects duplicate properties and nonfinite numbers. When needed it
removes fences or surrounding prose around one object, parses trailing commas,
single quotes, unquoted keys, Python literals, comments and raw controls, decodes
a JSON-encoded object string, then coerces existing primitives according to the
schema. Quoted literal text is never globally replaced. No evaluation, code
execution, network lookup, missing values, or schema defaults are used.

The schema subset supports types and nullable values, properties, required,
additionalProperties false, enum, const, items, array lengths, numeric bounds,
string lengths, and simple anyOf/oneOf. Unsupported keywords are ignored.
Boolean values are distinct from numbers. Coercion tries only existing values;
ambiguous conversions remain invalid, and a candidate must satisfy the complete
schema. Names are corrected only for a unique declared match, using case folding
or the final namespace component. Explicit `tool_choice` constraints are honored.

Text extraction runs only when no tool calls exist and the choice permits calls.
It recognizes Hermes/Qwen `<tool_call>` objects, GLM name-plus-object tags,
`<function=name>` blocks, fenced name/arguments or name/parameters objects,
ASCII tool-call tokens, and DeepSeek's Unicode function/separator tokens.
Only spans for declared names are removed. IDs use `safe_tool_id`; remaining
prose is retained. Extracted calls still undergo the same validation.

## Modes and integration

`X-MultiLLM-Tool-Repair: off | repair | full` overrides
`TOOL_CALL_REPAIR_DEFAULT` (default `repair`). Unknown values use the configured
default, and an unknown configured default uses `repair`. `off` adds counts but
leaves the existing response bytes and transport behavior intact.

`routes/tool_repair.py` wraps unified Chat and native Messages/Responses dispatch.
Native requests retain their provider endpoint; response repair uses the existing
native-to-Chat translators and then translates back. This inherits the documented
translation limits for provider extensions. Translation failure on a successful
native non-stream response leaves the original response usable. Free-pool repair
runs before the existing output gate. Intelligence repair runs before completion
validation, using a separate helper for token, attempt and deadline accounting.

In `full`, deterministic-invalid non-stream calls permit at most one same-model
follow-up per request. It carries the conversation, invalid assistant message,
and bounded tool/error instructions. Multiple completion choices are combined
into one follow-up with `n=1`, then corrected calls are restored to their original
choices and IDs. The reply must validate and retain the same call count; only
invalid calls are replaced. Failed or invalid replies leave the original invalid
calls. Known numeric usage fields from both responses are summed, including
cached/reasoning details. Intelligence uses its existing usage ledger and settles
both attempts; free-pool follow-ups count toward the pool attempt ceiling and
share its original deadline. Exhausted budgets skip the follow-up with
`reasked=0`. Provider refusal or transport failure after submission is counted as
an attempted re-ask. Streaming requests never re-ask, including providers that
answer them with JSON.

## Streaming and limits

Content and role deltas are emitted immediately. Function deltas accumulate by
choice/call index; completed calls are emitted as one complete delta per call
before the finish chunk, `[DONE]`, or error. Heartbeats, usage frames, and
unchanged frames are preserved. General Chat streams flush buffered calls at EOF.
Intelligence retains its existing terminal validation and stream-error handling.
No stream text extraction occurs because the text has already reached the client.

Limits are 128 declared tools/calls/choices, 64 KiB per argument string, 32 levels
of JSON nesting, 4,096 schema/value nodes, 32 validation errors, 256 KiB extraction
text, 128 scanned tagged calls and 128 fenced candidates, 1 MiB SSE frames, and
8 MiB response/tool buffers. Names/IDs in stream buffers are capped at 256
characters. Invalid shapes or exhausted limits retain original calls; oversized
SSE frames disable repair and forward remaining bytes. No unbounded repair store
or persistent state is introduced.

With declared tools, the response header is
`checked=<n> repaired=<n> extracted=<n> invalid=<n> reasked=<n>`. A stream's header
contains initial zero counts: HTTP headers cannot report final tool counts while
also sending content immediately. Counts-only `tool_call_repair` logs carry
model/provider and final counts. There are no custom body fields or SSE events.

## Verification and operation

Synthetic corpus tests cover every deterministic stage, extraction format,
ambiguous conversions, unknown names, missing required values, and malicious
syntax. Unit tests cover schema behavior, byte-preserving off mode, bounded
parsing, multiple choices, full-mode failures and usage, and streaming ordering,
EOF, heartbeats and limits. Mocked route tests cover native and translated
Messages/Responses, unified Chat, free pools, intelligence budgets, logs, and
streams. Worker tests cover environment forwarding and browser CORS.

Deploying these commits needs only the normal Worker and Container release.
Optionally set `TOOL_CALL_REPAIR_DEFAULT`; no schema or Durable Object migration
is needed. Production execution and provider-specific live behavior are outside
this local verification.
