# PII redaction and streaming rehydration

Opted-in managed generations replace detected PII before provider dispatch and
restore request-owned placeholders in JSON responses and SSE text. The credential
secret firewall runs first. Its findings, including values in secret-named fields,
never enter the reversible PII map, even when secret scanning observes rather than
redacts or blocks them.

## Configuration

The defaults leave traffic unchanged:

```text
PII_REDACTION_ENABLED=false
PII_REDACTION_POLICY_JSON={}
```

Empty values mean these defaults. Invalid flags or policies disable redaction and
produce one warning per configuration field, without including its value. Enabling
the flag with an empty policy opts in nothing. Unknown policy fields are invalid.

For example, opt in a managed route:

```text
PII_REDACTION_ENABLED=true
PII_REDACTION_POLICY_JSON={"routes":["/v1/chat/completions"],"keys":[],"detectors":["email","phone","card"],"mode":"required"}
```

Or opt in an authenticated key scope, using its stable internal identifier rather
than the credential itself:

```text
PII_REDACTION_POLICY_JSON={"routes":[],"keys":["key-7"],"detectors":["email"],"mode":"best_effort"}
```

Matching either an exact route or a key scope enables the selected detectors. An
empty detector list disables transformation. Flask scopes use the authenticated
user ID, falling back to the username. Native roleplay transport consumes the
authenticated scope supplied as `settings.piiKeyScope`; it never infers a scope
from a caller header. Worker roleplay scopes are SHA-256 fingerprints of the
authenticated token, set on the private Durable Object hop; caller scope headers
are overwritten. Route opt-in applies to all authenticated callers on that
route. Each list accepts at most 512 strings, each at most 256 characters; the
policy JSON accepts at most 64 KiB.

Managed Flask routes are `/v1/chat/completions`, `/v1/messages`, `/v1/responses`,
and `/intelligence/v1/chat/completions`. Native roleplay uses
`/v1/roleplay/chat/completions`. Raw passthrough is never transformed. Register
the Flask request hook after authentication, retention, injection checks and
batch spillover, before hosted Responses state, idempotency claims and
generation-cache lookup. Forward both configuration
variables to the Flask Container when using it behind the Worker.

## Detector coverage

Detectors examine JSON string values recursively, preserving object keys and
non-string values. Email matching uses bounded ASCII local parts and domain
labels; it does not recognize every valid international email address. Phone
matching accepts 10–15 digits with a leading plus or common spacing, parentheses,
or hyphens. Bare digit strings are not treated as phones. Card matching accepts
13–19 digits passing Luhn, excluding repeated identical digits. Matches do not
prove that a phone or card exists. Long, ambiguous numeric runs and formats outside
these limits can remain unchanged. There is no remote or semantic classifier.

## Request-local placeholders

The format is `__MLPII_<64 lowercase hexadecimal characters>__` (74 ASCII bytes).
The hexadecimal portion is HMAC-SHA-256 of the original value under a random
32-byte secret generated for that request. Repeated values share a placeholder
within one request. Separate requests have separate secrets and maps; they cannot
restore each other's tokens. Only exact tokens in the current request's map are
restored. Unknown or altered complete tokens pass through unchanged.

The map and secret remain in memory and are cleared on completion, error, or
disconnect, including cancellation before the first response chunk. They are not
logged, exported, cached, stored, or reused. A request permits at most 512 distinct
values and 1 MiB of serialized input, with a maximum JSON depth of 32 and 32,768
visited nodes. A collision fails the entire transformation.

## Streaming and errors

Restoration handles arbitrary network chunk boundaries, UTF-8 splits, JSON
escapes, and placeholder fragments across successive text deltas. It carries at
most 128 bytes of unresolved token prefixes across at most 16 text lanes. SSE
frames are limited to 64 KiB, nonstream JSON bodies to 1 MiB, and buffered output
from a single transport read to 1 MiB. Parser traversal
has the same depth and node limits as request traversal. Restored values are
serialized with JSON escaping. SSE events can move withheld text into a later
delta; their concatenated text retains the original order.

`required` is the default mode. A transformation or bound failure returns HTTP
422 with code `pii_redaction_failed` before dispatch. In `best_effort` mode, an
atomic transformation failure dispatches the unchanged firewall-checked payload
and records that redaction was skipped. A firewall refusal remains a refusal in
both modes. Policy validation errors disable the feature, rather than applying
required-mode rejection to existing traffic.

Invalid response JSON, a parser bound failure, or an unresolved terminal prefix
returns HTTP 502 with code `pii_rehydration_failed` for nonstream responses. A
stream that has already started is terminated with an error and its map cleared;
it does not invent a completion or authorize replay. Provider output must echo an
issued placeholder exactly to restore it. Rewritten or invented tokens cannot be
recovered. A trailing incomplete prefix is never emitted as successful text.

## Cache, replay, and operating limits

Redacted Flask requests use request-local zero-content retention, which bypasses
the exact, shared and semantic generation caches. Hosted opt-in or continuation
on such a request returns HTTP 400 `retention_conflict` before state storage.
An `Idempotency-Key` on a request that
actually requires redaction returns HTTP 400, `pii_idempotency_unsupported`, before
dispatch or replay. Requests with no PII retain their existing behavior.

Native roleplay transport reports `cacheable: false` and `replayable: false`
through `settings.onPIIDecision` for redacted requests. Its enclosing persistence
layer must honor that decision before storing any generation or replay body.
The transformed upstream request omits `Idempotency-Key`, and its request and
response carry `Cache-Control: no-store`. The request-local map is never part of
conversation state. Normal conversation retention is governed separately by the
content-retention policy.

Redaction adds local scanning, HMAC, and parsing work without classifier charges.
Long placeholders can increase provider input tokens and cost. Nonstream
restoration buffers a bounded body; streaming buffers a bounded frame and may
delay text while a token prefix is unresolved. This feature neither certifies a
provider's privacy guarantees nor removes the need to select the appropriate
retention policy. Verify detector coverage and provider echo behavior for the
formats used by the application.
