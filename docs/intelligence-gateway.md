# Intelligence gateway, version 1

`POST /v1/chat/completions` accepts `model: "auto:intelligence"` and the version-one
`routing` object. `POST /intelligence/v1/chat/completions` calls the same
implementation and defaults an omitted model to `auto:intelligence`. A concrete
`provider:model` with `routing` uses the same limits and accounting, stays pinned,
and never substitutes another model. Existing direct requests without `routing`,
other `auto:*` aliases and roleplay retain their existing policies.

The gateway is disabled until an operator supplies reviewed eligibility and
allowance settings. Source and synthetic HTTP tests do not establish deployed
provider availability. `/v1/models` advertises the alias, its reviewed capabilities,
and `availability: "unverified"`; it never reports credential presence as a live
probe. Native Gemini/Gemma/Vertex conversion paths are not eligible in version one
because their internal attempts do not yet share this accounting contract.

## Chat contract

```json
{
  "model": "auto:intelligence",
  "messages": [{"role": "user", "content": "Review this change."}],
  "max_tokens": 2048,
  "routing": {
    "version": 1,
    "task": "coding",
    "profile": "quality",
    "source": "jev",
    "required_capabilities": ["tools", "json"],
    "max_attempts": 3,
    "max_escalations": 1,
    "deadline_ms": 45000,
    "max_total_tokens": 16000,
    "allow_paid_overage": false
  }
}
```

Tasks: `general`, `coding`, `reasoning`, `planning`, `assessment`, `research`,
`writing`. Profiles: `fast`, `balanced`, `quality`. Sources: `jev`, `rules`,
`explicit`. Capabilities: `tools`, `json`, `vision`, `reasoning`, `streaming`,
`audio`. Omitted hints default to general/balanced/rules. Classification is
advisory: no Jev or judge request is made here. Omni owns intent classification,
conversation state, tools, approvals, execution and its run budget.

Messages, function tools, assistant tool calls and tool results are preserved.
Actual payload requirements supplement hints. `response_format`, explicit
`reasoning_effort`, output limits and streaming retain their meanings. Limits
are clamped to server ceilings; the gateway may further reduce the output limit
to fit the remaining aggregate token budget. Version one supports one choice
(`n: 1`), local JSON Schema references and standard function tools. Unknown
top-level fields, including provider billing overrides, are rejected. `routing`
is removed before transport. Requests with reasoning must select a model that
understands the supplied effort; the gateway does not rewrite explicit effort.

`X-Request-ID` is bounded and echoed in the header and `multillm.request_id`.
Model and correlation identifiers are limited to 128 safe characters.
`Idempotency-Key` is explicitly rejected with `idempotency_not_supported` in
version one. There is no exactly-once execution or uncertain-generation replay.

Successful responses carry the concrete selected `provider:model` in `model`
and `multillm.selected_model`. `multillm` includes `version: 1`, `request_id`,
`selected_provider`, `attempts`, `escalations`, `reason` and `usage_complete`.
Reasons are `policy`, `explicit`, `availability_fallback`, `quality_escalation`.
`attempts` counts dispatched submissions; skipped incompatible/unconfigured
candidates do not consume an attempt. Safe credential failures use the existing
401/402/403/404/429 fallback rules. Ambiguous timeouts, 5xx responses, malformed
responses and HTTP 200 error envelopes are failures and are never replayed.

Usage sums every generation, including invalid outputs that caused escalation.
Known usage fields remain available when another attempt has unknown usage;
`usage` is `null` when no usage is known. `usage_complete: false` tells Omni to
retain its reservation. A definite rejection contributes no generation usage.
Error envelopes use `error.code`, `error.message`, `error.retryable`, with a
validated `Retry-After` when provided. Error messages never include provider
bodies, credentials or exception strings.

Streaming uses Chat Completions SSE and indexed tool-call deltas. JSON and tool
streams are buffered within `max_response_bytes` until their output validates;
only then are their deltas released. Other streams deliver visible deltas as they
arrive. The terminal event contains aggregate `usage` and `multillm` before
`[DONE]`. An interruption emits a typed error event with incomplete accounting,
then `[DONE]`; `[DONE]` alone does not establish success. No provider replacement
is appended after output. Separate hidden reasoning fields are omitted.

A single deadline covers attempts and response consumption, including providers
that trickle bytes. Streaming heartbeat writes let WSGI observe disconnects while
the upstream is silent; cancellation prevents new submissions and stops response
consumption. An already accepted upstream operation may still finish remotely.
On Linux, Gunicorn and Werkzeug expose their client socket; polling its disconnect
events also stops non-streaming requests before a response write, without reading
or closing that socket. Other WSGI servers remain bounded by the overall deadline.
Production cancellation additionally depends on intervening proxies propagating
client disconnects. Uncertain reservations are retained in either case.

## Reviewed routing policy and storage

Start from [the disabled policy](intelligence-policy.example.json). Store secrets
only in the deployment secret manager. `INTELLIGENCE_POLICY_JSON` seeds an empty
policy table once; subsequent restarts preserve the stored policy and priorities.
The offline commands do not read `.env` or print policy values:

```sh
python scripts/intelligence_policy.py validate /path/to/reviewed-policy.json
python scripts/intelligence_policy.py seed /path/to/reviewed-policy.json
```

Each candidate needs this shape (identifiers and figures below are illustrative,
not reviewed availability or capability evidence):

```json
{
  "model": "nanogpt:reviewed-model-id",
  "enabled": true,
  "entitled": true,
  "privacy_allowed": true,
  "billing": "subscription",
  "capabilities": ["tools", "json", "reasoning", "streaming"],
  "context_window": 32768,
  "max_output_tokens": 4096,
  "quality_tier": 1,
  "task_scores": {"coding": 80, "reasoning": 75},
  "latency_ms": 1200
}
```

Review exact-model capabilities, context and output capacity, account entitlement
and privacy permission before enabling a candidate. Use task evaluations for
`task_scores` (0–100), an ordinal `quality_tier` (0–100) and measured latency for
`latency_ms`. Omit unknown measurements. No capability or quality is inferred
from model names or provider-wide flags. The balanced profile preserves operator
candidate order; fast prioritizes measured latency; quality prioritizes reviewed
task score and tier. A JSON/schema, tool-argument or required-tool validation
failure may escalate to a later candidate with a strictly higher reviewed tier.
It never uses model self-confidence as evidence. No free-pool retry policy is
applied to these requests.

Billing values are `subscription`, `allowance`, `free`, `payg`. Entitlement applies
to the configured credential pool; every member must be approved for this use.
Allowance/free accounts must have provider-enforced caps against paid spillover.
PAYG requires both server policy and caller opt-in; `false` still permits approved
subscriptions/allowances. NanoGPT subscription candidates always use the
subscription endpoint, irrespective of global speed routing; caller payment and
account headers are not forwarded. No implicit speed suffix is added. Reuse the
existing provider credential environment variables, base URLs and key cooldowns.
Intelligence dispatch does not trigger a credential probe.

Token admission conservatively estimates text/tool/schema input from UTF-8 bytes
plus framing overhead. Vision/audio chat candidates additionally require a
reviewed `media_input_tokens` ceiling. This is deliberately conservative, and
the reviewed ceiling must cover the accepted media workload. Oversized requests
fail before dispatch. `max_total_tokens` includes all attempts; an unknown attempt
consumes its entire per-attempt bound for subsequent admission.

The durable ledger atomically reserves each request's total token ceiling against
`principal_daily_tokens`, `global_daily_tokens` and `max_inflight`. Complete usage
settles that reservation. Pending and unknown outcomes remain charged across
restarts and beyond the rolling 24-hour allowance window; they never silently
expire. Reconcile them only after obtaining provider evidence. Keep an encrypted
backup before any operator correction; changing policy JSON or restarting is not
a reconciliation mechanism. No reconciliation endpoint is exposed in version one.

Local installations use the existing model-registry SQLite database. The Worker
requires durable storage for Containers. Its `INTELLIGENCE_DB` binding selects
[D1 intelligence storage](intelligence-d1.md), accessed through a private Container
outbound handler. D1 stores the reviewed policy, reservations and separately
provisioned integration credentials; it does not migrate dashboard users, model
overrides or automatic route priorities. These retain their existing storage.

Without the D1 binding, Container intelligence requires an external
`CONTROL_PLANE_DATABASE_URL`. PostgreSQL remains available for the full control
plane using the [encrypted empty-destination procedure](control-plane-storage.md).
Changing a `/tmp` pathname is insufficient. A configured database failure never
falls back to local storage. Seeding does not replace existing policy or users.

## Audio and embeddings

These routes require separate `media` entries and credentials, independently of
chat candidates. A key needs scope `audio` for transcription/speech and
`embeddings` for embeddings (admin keys already authorize both). This change does
not grant scopes or change existing account permissions.

Each `media.transcriptions`, `media.speech`, or `media.embeddings` entry contains
`candidate` in the reviewed candidate format, plus `max_input_bytes`,
`daily_requests`, and `principal_daily_requests`. Speech also requires `voice`;
embeddings requires `dimensions`. Supported raw media adapters are OpenAI,
NanoGPT and NavyAI. NanoGPT media cannot use the text subscription route; configure
an independently entitled allowance/free account or explicitly approved PAYG.
Media admission reserves one bounded submission against separate request-count
allowances. These are not token or monetary estimates for audio duration.

- `POST /v1/audio/transcriptions`: multipart `model: provider:model`, one `file`,
  optional `language`, `prompt`, `temperature`; `response_format` must be `json`.
  Returns `{"text":"..."}`.
- `POST /v1/audio/speech`: JSON `model`, `input`, optional matching `voice`,
  `response_format`, `speed`, `instructions`. Returns binary audio.
- `POST /v1/embeddings`: JSON pinned `model`, `input`, optional matching
  `dimensions`, `encoding_format: "float"`, `user`. Validates every returned
  vector's dimension and input index, rejects incomplete batches, and never
  changes models or dimension on failure.

All three routes submit once. A provider's 202 job acceptance returns a bounded
`id`, its actual pending status and the pinned model with HTTP 202; it is not
completed audio. Do not resubmit accepted jobs. Provider-specific job polling is
outside this version-one normalized surface. Input/output bytes and the overall
deadline bound these operations. Provider errors and unexpected JSON in a binary
speech response are failures.

Omni's current audio client expects synchronous transcription and speech. Use
synchronous models for that integration; consuming 202 job receipts requires a
separate client change. Configure the same pinned model/voice IDs in both systems.

## Local verification and deployment prerequisites

The focused tests use synthetic credentials, Flask HTTP routes and a real loopback
HTTP provider. They cover payload fidelity across fallback, eligibility, explicit
effort, JSON/tool escalation, payment/rate limits, uncertain timeouts, SSE
interruption/cancellation, aggregate usage, concurrent admission and persisted
reservations. Real local D1 tests exercise concurrent Worker replicas, persistence,
credential rotation and revocation. PostgreSQL integration tests additionally require an isolated
`TEST_CONTROL_PLANE_DATABASE_URL`; synthetic SQLite tests do not prove a production
database migration. No provider generation or deployment is performed by tests.

Before deployment, apply the D1 migrations or supply an external PostgreSQL database
and migrate existing records;
review exact models/accounts and task evaluations; set bounded principal/global
allowances; provision existing credential variables through the secret manager;
configure voice/model/dimension pins; and arrange approved scopes for Omni's key.
Run an authorized provider contract check before claiming live availability.
