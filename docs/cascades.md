# Verification-gated cascades

`cascade:<name>` tries two to four configured chat tiers in order. Unlike `auto:`,
a successful answer can escalate when verification fails. Save a cascade next to
**Automatic priorities** in Operations, or use the administrator-only
`GET /admin/cascades` and CSRF-protected `PUT /admin/cascades` endpoints.
The PUT body is the configuration itself; both endpoints return `{ "cascades": [...] }`.

```json
{
  "name": "cascade:short-answers",
  "tiers": [
    { "model": "free:text", "max_output_tokens": 512 },
    { "model": "auto:intelligence" }
  ],
  "checks": ["complete", "json", "tools", "no_refusal"]
}
```

Tier IDs can be concrete `provider:model` IDs, existing `auto:<name>` routes,
or free pools (`free:text`, `free:vision`). The configured `auto:intelligence`
policy is supported too. Nested cascades are rejected. Names follow automatic
route name rules. No cascade is enabled by default: choose the cost order for
your own configured models. Saved routes appear in `/v1/models` with
`owned_by: multillm-cascade` and respect API-key model allowlists.

Use the cascade model on `/v1/chat/completions`, `/optimize/v1/chat/completions`,
`/v1/responses`, or `/v1/messages`. The existing protocol translation layer
handles requests and responses; server-state features rejected for `auto:` are
rejected here too. Cascades require `n=1` and do not accept intelligence `routing`
overrides. A tier output cap also respects a lower caller token limit.

Checks run in this fixed order and stop at the first failure:

- `complete`: nonempty text or tool calls, no upstream error, and no `length` finish.
- `json`: only for requested JSON object/schema output; strict parsing and the
  existing tool-argument schema validator apply.
- `tools`: declared tool calls must validate after deterministic repair. Repaired
  calls are returned to the caller. A `tool_choice` of `"required"` or a named
  function requires a valid call to an allowed tool; prose alone fails.
  Internal repair reasks are disabled so escalation owns subsequent calls and
  their accounting.
- `no_refusal`: only a whole short refusal, explicit empty refusal, or existing
  refusal sentinel fails; discussion containing refusal language passes.
- `agreement`: opt-in second call using `agreement.model`, or the tier model by
  default. Answers over 300 trimmed characters and tool calls skip comparison.
  Short answers use Unicode/case/whitespace normalization; numeric answers
  compare numerically. When the agreement model equals the tier model, the
  second sample uses `temperature: 1` without `top_p` or `seed`. A different
  agreement model retains the caller's sampling fields. Failed calls or unusable
  comparison output pass with an `agreement_error` note; an actual mismatch fails.
- `judge`: opt-in `{ "judge": { "model": "provider:model", "min_score": 7 } }`.
  The model scores answer text against the last plain-text user message with
  strict JSON. Tool-call answers and non-text final turns (including tool results)
  skip judging as a pass, with no judge call or charge. Up to 4,096 text-only
  content blocks are supported; larger lists also skip judging. Request and
  answer text are each limited to 16,000 characters
  before JSON encoding; reasoning fields and raw message objects are excluded.
  Finite scores 0–10 below the threshold fail. Judge calls use 1,024 output tokens;
  failures, empty content, and malformed or out-of-range scores pass with a
  `judge_error` note. The secret firewall remains mandatory for every call.

Routed agreement and judge models (`free:*`, `auto:*`) exclude Gemini; an
explicit concrete Gemini choice is allowed. Auxiliary models, tier aliases,
and the actual concrete candidates must each match the API-key allowlist.
Every dispatched tier/agreement/judge uses the existing admission, budget,
rate-limit, ledger, telemetry and secret-firewall path. These subrequests replace
the outer aggregate charge; SSE replay adds no charge. Normal provider failover
remains inside the dispatched subrequest. A free tier records one ledger row
for the dispatched pool call and reports its concrete selected candidate. Free
route health and quota handling remain owned by the free-route dispatcher.

Non-final tiers run buffered: the entire tier answer and its checks finish
before streaming clients receive the first byte. This adds latency before SSE
starts, including any auxiliary verification calls and failed earlier tiers.
A passing tier replays through standard SSE helpers for streaming clients. The
final tier is unchecked and uses the client's stream setting. The receipt is
exposed through both Container and Worker CORS:

```text
X-MultiLLM-Cascade: tier=2/3; model=opencode:example; skipped=1:json
```

When advisory checks fail, the receipt adds a nonempty notes field, for example:

```text
X-MultiLLM-Cascade: tier=1/2; model=opencode:example-free; skipped=; notes=1:agreement_error,1:judge_error
```

`notes` lists `<tier>:judge_error` or `<tier>:agreement_error` and is omitted
when empty. Notes persist if a later check escalates the tier. A skipped judge
does not produce an error note. Secret-firewall rejection remains a blocking
error for both advisory checks.

Admission or upstream errors can also report `admission` or `complete`;
`deadline` identifies work omitted for lack of time. The request timeout is
shared across tiers and rechecked before nested provider sends. Another call is
started only when the remaining time covers the previous call's elapsed time
(at least one second). If work stops, the usable answer that passed the most
checks wins, with the later answer breaking ties. If no usable answer exists,
the previous failure response is retained or the normal dispatch error returns.
A final answer is always passed through once the final tier runs.

## Storage and deployment

Apply `intelligence-migrations/0012_cascades.sql` to the existing
`multillm-intelligence` D1 database before deploying. No new binding, variable,
Durable Object migration, or dependency is required. Local mode stores cascades
in the model-registry SQLite database. D1 access uses the private
`intelligence.internal/v1/cascades` list/put RPC; it never accepts an arbitrary URL.
There are at most 200 cascades, four tiers, six checks, 256-character model IDs,
and 1,048,576 tokens per configured cap. Private requests are capped at 16 KiB;
list responses at 512 KiB. Reads cache for 30 seconds, retaining the last good
configuration during an outage and retrying after 10 seconds. Failed writes
return 503 and never report a successful save. Verification buffers at most
1 MiB of answer bytes and 4,096 chunks within the deadline; oversized or
interrupted answers escalate without unbounded buffering.

Paid tiers, agreement calls, and judges can incur extra provider cost. Set
allowlists and budgets and choose existing chat-capable automatic routes before
enabling a cascade. Provider timeouts limit individual sends; no synchronous
HTTP transport can guarantee a precise wall-clock cancellation of an in-flight
stream. Validation evidence is local and synthetic; no live inference,
deployment, or remote migration was performed.
