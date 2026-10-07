# Verification-gated cascades

## Contract and configuration

The virtual namespace is exactly `cascade:<name>`. It serves the four unified
chat API surfaces through the existing automatic-route protocol translation.
Configuration contains `name`, two to four `{ model, max_output_tokens? }` tiers,
`checks`, optional `{ model, min_score? }` judge (threshold defaults to 7),
optional `{ model? }` agreement (defaults to the current tier), and server-owned
`updated_at`. Names follow automatic route syntax. Tiers are concrete provider
models, existing automatic routes (including configured `auto:intelligence`),
or free pools (`free:text`, `free:vision`), never recursive cascades. For example,
`[{ "model": "free:text" }, { "model": "auto:intelligence" }]` starts free
and escalates only after a failed check.
`services/cascade_config.py` owns bounded, strict normalization; the edge mirrors
it in `worker/cascades-d1.mjs`. Administrator saves validate provider and route IDs.

D1 migration `0013_cascades.sql` creates `cascades(name, config, updated_at)`.
`services/cascade_service.py` uses private D1 in deployed mode and model-registry
SQLite locally. Both support the empty default seed set: operators select their
cost order rather than enabling unspecified paid tiers. The private list/put RPC
is bounded to 200 configurations. `cascade_d1.py` caches normalized copies for
30 seconds, retains the last good read on outage, retries after 10 seconds, and
fails writes visibly. Operations exposes a validated JSON editor next to automatic
priorities. Models discovery adds `owned_by: multillm-cascade` entries.

## Verification and dispatch

`routes/cascades.py` orchestrates calls; `services/cascade_checks.py` owns checks.
Checks run complete, json, tools, no_refusal, agreement, judge, stopping on failure.
Complete rejects errors/empty output/length. JSON parsing is strict; schema
validation reuses `validate_arguments`. Tools use `repair_tool_calls(mode="repair")`
and return repaired calls. Required/named `tool_choice` also requires a valid
call of an allowed name; prose alone fails. Refusal detection is conservative
and whole-answer.
Agreement compares only text of at most 300 trimmed characters, normalizes Unicode,
case and whitespace, and compares finite numbers numerically. Long/tool answers skip.
Same-model second samples use `temperature: 1` and omit `top_p` and `seed`; a
different agreement model retains client sampling. Call errors or unusable comparison
output pass with an `agreement_error` note, while actual disagreement escalates.
Judge output is strictly one finite numeric score from 0 to 10; below the configured
threshold escalates, while malformed/empty output, out-of-range scores or judge errors
pass with a `judge_error` note. Tool-call answers and non-text final turns (including
tool results) skip the judge with no call or ledger row. For other turns, the judge
receives a short rubric against the last plain-text user message, 1,024 output tokens,
and only the answer's text content. Request/answer text are each bounded to 16,000
characters before JSON encoding, preserving valid JSON and excluding reasoning fields.
Up to 4,096 text-only content blocks are supported; larger lists skip judging.

Non-final tiers are internally non-streaming, with at most 1 MiB inspected bytes.
The full non-final answer and checks complete before the first byte reaches a
streaming client, adding latency from generation, checks and prior failed tiers.
A passing tier returns buffered JSON or replays standard SSE. The final tier is
unchecked and passes through with the original streaming setting. The receipt is
`X-MultiLLM-Cascade: tier=i/n; model=provider:model; skipped=tier:check,...`,
exposed by both CORS lists and retained by the existing chat cache. Nonempty advisory
notes append `; notes=tier:judge_error,tier:agreement_error,...`; empty notes are
omitted. Notes persist across escalation, and skipped judges add no note.

Every gateway-owned tier, agreement, and judge uses `accounted_dispatch` and
`release_outer_accounting`; final streams reuse the standard close-time usage
settlement. No additional accounting implementation is introduced. Normal dispatch
continues through `make_request`, preserving the outbound firewall and scanned-byte
reuse. Routed judges/agreements run within `excluding_gemini`, while deliberate
concrete Gemini models remain allowed. Cascades, tier IDs, auxiliary IDs and nested
concrete candidates each respect key allowlists. Automatic/free health and
failover remain owned by their existing dispatchers; concrete tier attempts
report health through
the existing service. Each free pool dispatch gets one ledger row and its concrete
selected candidate appears in the cascade header.
Internal tool reasks are suppressed while cascade orchestration owns requests.

## Deadline and failure policy

The request's configured timeout is shared across calls, capped at 600 seconds,
with concrete/nested provider sends rechecking the deadline. Another tier/check
needs the prior call's elapsed time (at least one second) remaining. Deadline or
later budget/rate admission failure returns the usable previous answer that passed
the most checks, choosing the latest on ties. A previous failure response is kept
when no usable answer exists; a terminal dispatch exception uses the normal error.
Secret-firewall rejection is never softened into judge success.

Cascades reject `n` other than 1 and intelligence routing overrides to keep a
single explicit answer/configuration contract. Stateful features follow automatic
routes' rejection rules. Additional bounds and operational details are in
[cascades](../cascades.md). No binding/variable/DO changes are required; operators
must apply migration 0013 to existing D1 before deployment.

## Verification

Synthetic tests cover every check and failure path, schema/tool repair, numeric
agreement, judge pass/fail/error, scoped Gemini exclusion, deadline fallback,
allowlists, buffering bounds, ledger row counts, stream replay/pass-through,
all four API endpoints, SQLite/D1 storage, dashboard save/CSRF, models discovery,
CORS and the frozen secret-firewall route/module inventories. Existing Python,
Worker, and Knowledge suites provide integration regression coverage. No deployed
gateway or production service is used for acceptance evidence.
