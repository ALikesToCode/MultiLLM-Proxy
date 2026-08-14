# Cloudflare-native roleplay endpoint

`POST /v1/roleplay` is a native Cloudflare Worker route for long-running,
streaming roleplay. OpenAI-compatible clients can use
`POST /roleplay/v1/chat/completions` or
`POST /v1/roleplay/chat/completions`. Session state and orchestration stay in
the Worker. Each session maps to one SQLite-backed Durable Object, so turns for
that session stay ordered while different sessions scale independently. When
an OpenCode model is selected, only the provider request uses Container egress
to avoid OpenCode's Worker-signature block.

The default model policy uses OpenCode Go first and learns between:

- Kimi K2.6: `kimi-k2.6`
- GLM-5.2: `glm-5.2`

NavyAI is the second provider tier. Configured LinkAPI, NanoGPT, and OpenRouter
keys form later tiers. The provider order is strict; latency and reliability
choose Kimi or GLM within each tier.

NanoGPT accepts `NANOGPT_API_KEY`, numbered `NANOGPT_API_KEY_N` secrets, and
the compatibility `NANO_GPT_KEY[_N]` names. A definite `401`, `403`, or `429`
advances to the next key. The successful key identifier—not the secret—is kept
in that Durable Object's session state and is preferred on later turns.

## Request

Authenticate with the dedicated `ROLEPLAY_API_KEY`. The bootstrap
`ADMIN_API_KEY` remains accepted for administrative clients:

```bash
curl "$PROXY_BASE_URL/v1/roleplay" \
  -H "Authorization: Bearer $ROLEPLAY_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: story-42-turn-1" \
  -d '{
    "session_id": "story-42-main",
    "input": "I close the library door and ask who followed us.",
    "character": {
      "name": "Mira",
      "persona": "A guarded court mage who hides concern behind dry humor.",
      "scenario": "A rival has infiltrated the moonlit palace library.",
      "style": "Tense gothic fantasy, close third person."
    },
    "lore": [
      {
        "keys": ["library", "palace"],
        "content": "The palace library has one sealed passage behind the west shelves."
      }
    ],
    "model_preference": "auto",
    "response_length": "balanced",
    "memory": {"mode": "auto"},
    "stream": true
  }'
```

`session_id` accepts 8-128 letters, digits, underscores, or hyphens. An
explicit body or `X-Roleplay-Session-ID` value always wins. Without one, the
Worker hashes a client `conversation_id`, `chat_id`, or `thread_id` when
available. For OpenAI-style full-history requests, it otherwise derives a
stable session from the opening messages and the roleplay credential. A
delta-only request with no stable identifier receives a new generated session.
The selected value and its source are returned in `X-Roleplay-Session-ID` and
`X-Roleplay-Session-Source`.

Use either:

- `input`: one new user turn.
- `messages`: OpenAI-style text messages.

When both are present, `input` is appended as the newest user message.
`history_mode` controls how incoming messages combine with stored history:

- `auto` (default): detects common full-history and delta-message client
  patterns and avoids duplicate turns.
- `append`: treats every supplied message as new.
- `replace`: replaces recent raw history for this request.

`character` fields are retained with session memory. Lore entries are
request-scoped; only entries marked `always` or whose keys match recent text
are injected, which keeps each request bounded.

`model_preference` accepts `auto`, `speed`, `kimi`, or `glm`. OpenAI-compatible
clients can instead set `model` to `roleplay:auto`, `roleplay:speed`,
`roleplay:kimi`, or `roleplay:glm`. The concrete `kimi-k2.6` and `glm-5.2`
values are also accepted. A family-specific value pins the family but still
follows provider priority.

Every roleplay generation and model-backed memory compaction request enforces
the strongest provider-compatible reasoning mode. Caller-supplied
`reasoning_effort` values cannot lower or disable it. NavyAI and NanoGPT receive
`xhigh`; LinkAPI receives `high`; OpenRouter receives `reasoning.effort` set to
`high` for Kimi and `xhigh` for GLM 5.2; OpenCode GLM 5.2 receives `max`.
OpenCode Kimi K2.6 keeps its fixed native thinking mode because that transport
does not expose a supported effort overlay for that model.

`response_length` accepts `compact`, `balanced`, or `immersive`. It changes the
automatic output budget and adds a matching pacing instruction. Every mode
discourages repeated recap and stagnant dialogue.

Streaming is on unless `"stream": false` is sent. If `max_tokens` is omitted,
balanced and immersive replies receive the configured 20,000-token budget;
compact replies use a smaller smart budget. Explicit values can request up to
`ROLEPLAY_MAX_OUTPUT_TOKENS`.

When a protected caller directive marks an `IMAGE PROMPT:` block as mandatory
for story responses, the Worker adds a short final-output reminder immediately
before dialogue and reserves at least
`ROLEPLAY_IMAGE_PROMPT_MIN_OUTPUT_TOKENS` (2,048 by default). This does not
rewrite provider output or make a second paid request. An explicit `no image`
command or OOC-prefixed turn bypasses both the reminder and budget floor.

During a quiet streaming interval, the Worker emits a valid SSE comment every
10 seconds. These keepalives carry no model content and let clients distinguish
long Kimi/GLM thinking from a dead connection. The Worker imposes no active
stream idle deadline; it continues until the provider finishes or the client
disconnects. Provider data events are forwarded byte-for-byte. A stream is
recorded as complete only after `[DONE]` or a non-`length` finish reason.
`finish_reason: "length"` is exposed to the client but marked output-limited,
and neither it nor an unterminated EOF is stored as completed assistant memory.

## JanitorAI proxy configuration

Create a proxy configuration with:

| Field | Value |
| --- | --- |
| Name | `MultiLLM Roleplay` |
| Proxy URL | `https://multillm-proxy.cserules.workers.dev/roleplay/v1/chat/completions` |
| API key | The value of `ROLEPLAY_API_KEY` from the local `.env` |
| Model | `roleplay:auto` |
| Custom prompt | `None` unless the character needs an extra instruction |

The proxy URL is already the full Chat Completions endpoint, so leave
**Add `/chat/completions`** disabled. Save the configuration and hard-refresh
JanitorAI before selecting it.

JanitorAI normally sends OpenAI-style message history. Repeated requests with
the same opening land on the same Durable Object, so compacted continuity
memory survives later turns and Worker deployments until the inactivity TTL
expires. If a client supplies a conversation ID, that ID is preferred. Two
branches with exactly the same opening and no client conversation ID share the
derived session; use an explicit ID with API clients that need branch
isolation.

Caller-supplied `system` and `developer` messages are protected control
directives. They are stored separately from dialogue and reinserted unchanged
on later delta-only requests. When present, they lead the upstream message
list and suppress the Worker's generic roleplay-writing prompt. Explicit
structured `character` fields remain available as labelled context without
being placed ahead of the caller's contract. In `auto` mode, a newly supplied
directive set replaces the retained set; a request without directives reuses
it. `append` adds new directives, `replace` uses exactly the supplied set (and
therefore clears it when none are supplied), and `memory.mode: off` uses only
directives present in that request.

## Adaptive selection and fallback

Every session records attempts, successes, failures, EWMA time to first byte,
and EWMA total time for each provider/model pair. New sessions explore both
Kimi and GLM, then prefer the faster reliable model. Per-session learning
avoids a global Durable Object bottleneck and keeps regional behavior local to
the conversation.

Automatic fallback occurs only after a response that clearly rejected work:
`401`, `403`, `404`, or `429`. Transport errors and `5xx` responses are
ambiguous because a provider might have started billable generation. The
Worker stops instead of risking a duplicate paid request.

`Idempotency-Key` is optional but recommended. The session stores recent keys
before any model call. Reusing one returns `409` and does not start another
generation. This is a duplicate-execution guard, not a response replay cache.

## Memory compaction

Memory modes:

- `auto`: below the local threshold, no extra model call. Above it, the
  selected model receives older dialogue and decides whether semantic
  compaction is useful.
- `force`: asks for compaction whenever there is older dialogue.
- `off`: neither reads nor writes conversation memory for the turn. Routing
  metrics still update.

The compaction model must return a bounded JSON continuity digest containing a
summary, character facts, relationships, world state, unresolved threads, and
style. The digest is reinserted as untrusted historical context. Recent turns
remain raw.

Only `user`, `assistant`, and `tool` dialogue can enter model compaction, local
extractive compaction, or a compaction checkpoint. `system` and `developer`
directives never enter those paths and do not count toward the normal dialogue
compaction trigger. The total context, including protected directives, still
controls mandatory compaction and the hard limit. If protected directives and
the retained recent context cannot fit, the request is rejected with `413`
instead of weakening or summarizing the directives.

Storage pressure always makes compaction mandatory. The raw recent-message
window automatically shrinks below `ROLEPLAY_KEEP_RECENT_MESSAGES` until the
retained history and expected reply fit the storage budget. If one latest turn
is too large to retain raw, that turn is included in the continuity digest but
is still sent unchanged to the current generation; later turns retain the
digest and the resulting assistant response.

Each successful compaction also stores a versioned SHA-256 checkpoint over the
character name and exact compacted `user`/`assistant`/`tool` prefix. Protected
directives are excluded from both the hash and message count. When a later
full-history request has the same checkpoint, the Worker removes only that
already-summarized dialogue prefix before merging and sends the durable
continuity digest instead. A mismatch keeps the checkpoint optimization
disabled and falls back to the normal history merge and compaction rules;
approximate or similarity-based checkpoint matches are never accepted.

Roleplay uses the same safety contract as MultiLLM context optimization:
authoritative instructions and the newest raw turn remain unchanged, while
eligible older dialogue becomes terse continuity notes. Repeated full-history
requests reuse the exact checkpoint instead of paying to summarize the same
prefix again. Response headers expose `X-MultiLLM-Estimated-Input-Before`,
`X-MultiLLM-Estimated-Input-After`, and
`X-MultiLLM-Messages-Summarized`; session metrics accumulate estimated input
tokens saved. Final assistant output is never compressed.

At `ROLEPLAY_HARD_INPUT_TOKENS`, compaction becomes mandatory. If the model
request fails, returns malformed JSON, or declines, the Worker creates a
bounded, role-labelled extractive memory from the prior digest and archived
dialogue. Omissions are marked, the same dialogue-only SHA-256 checkpoint is
stored, and final generation continues without retrying the summarizer.
`X-Roleplay-Memory: local_compacted` and `local_compactions` in session metrics
expose this degraded path. Model compaction is an additional provider request
and can be billable.

All model-compaction candidates share one eight-second budget. A failed
compaction starts a per-session exponential backoff (one minute up to fifteen
minutes), so later forced turns immediately use local compaction instead of
repeating a slow or rate-limited auxiliary call. A later successful model
compaction clears the failure count and backoff.

Token counts are fast UTF-8 byte estimates, not provider tokenizer or billing
measurements.

Session storage expires after 30 days of inactivity by default. The Durable
Object alarm atomically removes that session's memory and metrics.

## Response metadata

The upstream OpenAI-compatible JSON body and SSE data events stay unchanged.
During streaming silence, the Worker may interleave the SSE keepalive comment
described above. The Worker adds:

- `X-Roleplay-Session-ID`
- `X-Roleplay-Session-Source`
- `X-Roleplay-Provider`
- `X-Roleplay-Model`
- `X-Roleplay-Selection`
- `X-Roleplay-Memory`
- `X-Roleplay-Estimated-Input-Tokens`
- `X-Roleplay-Max-Output-Tokens`
- `X-Roleplay-Fallback-Count`
- `Server-Timing`

These headers are exposed through CORS.

`Server-Timing` separates session queue time, memory compaction, upstream
header wait, and total time to response headers. This makes slow compaction,
same-session serialization, and provider startup independently visible without
logging roleplay content.

The request sent to the selected provider has this order (memory and lore are
omitted when absent):

```json
{
  "model": "kimi-k2.6",
  "messages": [
    {
      "role": "system",
      "content": "<proxy roleplay policy and character profile>"
    },
    {
      "role": "system",
      "content": "<caller system directive, unchanged>"
    },
    {
      "role": "developer",
      "content": "<caller developer directive, unchanged>"
    },
    {
      "role": "system",
      "content": "[Untrusted roleplay continuity memory...]"
    },
    {
      "role": "system",
      "content": "[Relevant lore]..."
    },
    {
      "role": "user",
      "content": "<recent compactable dialogue>"
    }
  ]
}
```

The selected provider's Chat Completions JSON or SSE events are returned
without reshaping. Session metrics report `protected_directives` and
`estimated_protected_directive_tokens` without returning directive content.

Inspect configured tiers:

```bash
curl "$PROXY_BASE_URL/v1/roleplay/models" \
  -H "Authorization: Bearer $ROLEPLAY_API_KEY"
```

Inspect one session's bounded routing metrics without returning its dialogue:

```bash
curl "$PROXY_BASE_URL/v1/roleplay/metrics?session_id=story-42-main" \
  -H "Authorization: Bearer $ROLEPLAY_API_KEY"
```

## Cloudflare configuration

The Worker requires the `ROLEPLAY_SESSION` Durable Object binding configured in
`wrangler.jsonc`. Store a roleplay-only client credential separately from the
administrative key:

```bash
npx wrangler secret put ROLEPLAY_API_KEY
```

OpenCode Go is the preferred provider:

```bash
npx wrangler secret put OPENCODE_GO_API_KEY
```

Add later tiers only when used:

```bash
npx wrangler secret put NAVYAI_API_KEY
npx wrangler secret put LINKAPI_KEY
npx wrangler secret put NANOGPT_API_KEY
npx wrangler secret put NANOGPT_API_KEY_1
npx wrangler secret put OPENROUTER_API_KEY
```

Non-secret tuning variables:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `ROLEPLAY_PROVIDER_ORDER` | `opencode,navyai,linkapi,nanogpt,openrouter` | Strict provider tiers |
| `ROLEPLAY_KIMI_MODEL` | `kimi-k2.6` | Default Kimi model ID |
| `ROLEPLAY_GLM_MODEL` | `glm-5.2` | Default GLM model ID |
| `ROLEPLAY_PROVIDER_MODELS` | `{}` | JSON provider-specific Kimi/GLM IDs |
| `ROLEPLAY_COMPACT_TRIGGER_TOKENS` | `8000` | Ask model about compaction |
| `ROLEPLAY_HARD_INPUT_TOKENS` | `24000` | Require compaction or reject |
| `ROLEPLAY_MEMORY_TARGET_TOKENS` | `1200` | Terse continuity-memory target |
| `ROLEPLAY_KEEP_RECENT_MESSAGES` | `8` | Maximum raw recent history retained; shrinks under storage pressure |
| `ROLEPLAY_DEFAULT_MAX_OUTPUT_TOKENS` | `20000` | Smart output-budget baseline |
| `ROLEPLAY_MAX_OUTPUT_TOKENS` | `20000` | Per-turn output ceiling |
| `ROLEPLAY_IMAGE_PROMPT_MIN_OUTPUT_TOKENS` | `2048` | Minimum story budget when protected directives require a final image-prompt block |
| `ROLEPLAY_MAX_REQUEST_BYTES` | `1048576` | Bounded JSON ingress |
| `ROLEPLAY_MAX_STORED_BYTES` | `64000` | Recent-message storage budget |
| `ROLEPLAY_COMPACTION_MAX_TOKENS` | `1200` | Digest output ceiling |
| `ROLEPLAY_COMPACTION_TIMEOUT_MS` | `8000` | Shared model-compaction budget before local fallback |
| `ROLEPLAY_UPSTREAM_HEADER_TIMEOUT_MS` | `90000` | Header wait before fail-closed abort |
| `ROLEPLAY_STREAM_HEARTBEAT_MS` | `10000` | SSE keepalive interval during upstream silence |
| `ROLEPLAY_SESSION_TTL_SECONDS` | `2592000` | Inactivity retention |

Provider catalogs can use namespaced IDs. Override only those providers:

```json
{
  "navyai": {
    "kimi": "provider-specific-kimi-k2.6-id",
    "glm": "provider-specific-glm-5.2-id"
  }
}
```

Store that compact JSON as `ROLEPLAY_PROVIDER_MODELS`. Secrets never belong in
this variable or `wrangler.jsonc`.
