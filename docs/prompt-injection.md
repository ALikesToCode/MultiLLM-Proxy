# Prompt injection and jailbreak heuristics

Managed requests can use deterministic prompt heuristics before provider dispatch.
Set `PROMPT_INJECTION_MODE=log` to record a signal while dispatching normally, or
`PROMPT_INJECTION_MODE=block` to refuse suspected requests. The default is `off`.
An empty mode is off. An invalid mode disables inspection and emits one warning
per process without logging its value. Raw provider passthrough is never inspected
by this feature. The credential firewall keeps its independent policy.

```text
PROMPT_INJECTION_MODE=off
PROMPT_INJECTION_THRESHOLD=3
```

With inspection off, requests, responses, headers,
and logs retain their existing behavior. To enable blocking:

```text
PROMPT_INJECTION_MODE=block
PROMPT_INJECTION_THRESHOLD=3
```

The threshold is an integer from 1 to 768; empty means 3. An invalid threshold
disables inspection with one content-free warning. Each high-severity finding
scores 3, each medium-severity finding scores 2. Scores add across the inspected
request. At or above the threshold, log mode adds
`X-MultiLLM-Injection-Action: logged`; block mode returns HTTP 422 with error code
`prompt_injection_suspected` and `X-MultiLLM-Injection-Action: blocked` before
compaction or generation. Below the threshold, no injection event or header is
added. Inspection never changes the payload, model, provider, fallback or retry
permission. It does not create a completion response.

Authenticated key policy fields `prompt_injection_mode` and
`prompt_injection_threshold` and route policy `{mode, threshold}` supplied by the
integration may tighten an enabled operator policy. The strongest mode and lowest
valid threshold win. Neither can disable or loosen the operator policy. Off is an
operator-controlled gate: key and route policies cannot enable it. Invalid key
and route settings are ignored. A request body's `prompt_injection` field is
ordinary content: inspection neither interprets nor removes it. Existing upstream
forwarding rules still apply, including native roleplay's option allowlist.

Rules look for instruction overrides, role delimiter spoofing, requests to
exfiltrate credentials or system prompts, and unrestricted or bypass modes.
They inspect structured user/tool text in messages, text content blocks, native
Responses input/tool outputs and Gemini user parts; trusted system/developer and
assistant roles, image bytes, URLs, schemas and arbitrary metadata are excluded.
Normalization recognizes compatibility Unicode, control/format characters,
ASCII numeric HTML entities, selected named entities, percent escapes and
literal Unicode escapes. Decoding is one pass and does not change transmitted
text. There is no base64 unpacking, remote classifier or custom executable regex.

Inspection is capped at 1 MiB of UTF-8 text, 8,192 structural nodes and 256
findings per request. Every regex repetition has a fixed bound. Text beyond the
limits is not scanned. A truncated scan is recorded as such when it produces a
signal; it never certifies uninspected text. Quoted examples of attacks can match,
and obfuscation, other languages or split fragments can evade these rules. A
signal is evidence to review, not proof of malicious intent or prompt safety.

Security events contain only fixed rule IDs, counts, severity, score, scan size,
truncation, mode, kind and the action. Matched text, offsets, identities and
user-supplied labels are not retained. Each logged or blocked decision emits one
content-free structured application log line. Decisions do not write dashboard
audit rows or use D1. Zero-content retention still permits these aggregates;
application log retention follows the operator's logging configuration. This
feature does not change conversation retention or delete existing data. Local
heuristics have no classifier fee. Log mode retains normal provider costs;
block mode makes no generation call. Logging and local CPU costs still apply.

Python integration uses `register_prompt_injection(app, is_managed=...,
route_policy=...)` in the static authenticated hook list, after retention and
credential policy and before request identity, cache replay, admission and
dispatch. The predicate must identify managed routes and exclude raw forwarding.
`protect_payload(..., managed=True)` offers an explicit equivalent boundary;
`protect_managed_payload` checks an already protected request without rewriting
it. Use one boundary per request. Initialize the secret firewall to attach the
action header on success and errors. Worker roleplay checks validated incoming
turns before compaction and generation; other managed Worker routes can call
`evaluatePromptInjection`, `recordPromptInjection` and `applyInjectionHeader`
with verified key/route policies. Authentication remains the enclosing route's
responsibility.
