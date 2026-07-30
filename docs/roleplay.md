# Cloudflare-native roleplay endpoint

`POST /v1/roleplay` is a native Cloudflare Worker route for long-running,
streaming roleplay. It does not wake the Flask Container. Each session maps to
one SQLite-backed Durable Object, so turns for that session stay ordered while
different sessions scale independently.

The default model policy uses OpenCode Go first and learns between:

- Kimi K2.6: `kimi-k2.6`
- GLM-5.2: `glm-5.2`

NavyAI is the second provider tier. Configured LinkAPI, NanoGPT, and OpenRouter
keys form later tiers. The provider order is strict; latency and reliability
choose Kimi or GLM within each tier.

## Request

Authenticate with the bootstrap `ADMIN_API_KEY`:

```bash
curl "$PROXY_BASE_URL/v1/roleplay" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
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

`session_id` accepts 8-128 letters, digits, underscores, or hyphens. If it is
omitted, the Worker creates one and returns it in
`X-Roleplay-Session-ID`. Send that value on later turns in the body or
`X-Roleplay-Session-ID`.

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

`model_preference` accepts `auto`, `speed`, `kimi`, or `glm`. A family-specific
value pins the family but still follows provider priority.

`response_length` accepts `compact`, `balanced`, or `immersive`. It changes the
automatic output budget and adds a matching pacing instruction. Every mode
discourages repeated recap and stagnant dialogue.

Streaming is on unless `"stream": false` is sent. If `max_tokens` is omitted,
the Worker derives a bounded output budget from the newest user turn. Explicit
values cannot exceed `ROLEPLAY_MAX_OUTPUT_TOKENS`.

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

At `ROLEPLAY_HARD_INPUT_TOKENS`, compaction becomes mandatory. If it fails or
declines, the endpoint returns an error before final generation. It never
silently discards history to make a request fit. Compaction is an additional
provider request and can be billable.

Token counts are fast UTF-8 byte estimates, not provider tokenizer or billing
measurements.

Session storage expires after 30 days of inactivity by default. The Durable
Object alarm atomically removes that session's memory and metrics.

## Response metadata

The upstream OpenAI-compatible JSON or SSE body stays unchanged. The Worker
adds:

- `X-Roleplay-Session-ID`
- `X-Roleplay-Provider`
- `X-Roleplay-Model`
- `X-Roleplay-Selection`
- `X-Roleplay-Memory`
- `X-Roleplay-Estimated-Input-Tokens`
- `X-Roleplay-Max-Output-Tokens`
- `X-Roleplay-Fallback-Count`
- `Server-Timing`

These headers are exposed through CORS.

Inspect configured tiers:

```bash
curl "$PROXY_BASE_URL/v1/roleplay/models" \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

Inspect one session's bounded routing metrics without returning its dialogue:

```bash
curl "$PROXY_BASE_URL/v1/roleplay/metrics?session_id=story-42-main" \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

## Cloudflare configuration

The Worker requires the `ROLEPLAY_SESSION` Durable Object binding configured in
`wrangler.jsonc`. OpenCode Go is the preferred provider:

```bash
npx wrangler secret put OPENCODE_GO_API_KEY
```

Add later tiers only when used:

```bash
npx wrangler secret put NAVYAI_API_KEY
npx wrangler secret put LINKAPI_KEY
npx wrangler secret put NANOGPT_API_KEY
npx wrangler secret put OPENROUTER_API_KEY
```

Non-secret tuning variables:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `ROLEPLAY_PROVIDER_ORDER` | `opencode,navyai,linkapi,nanogpt,openrouter` | Strict provider tiers |
| `ROLEPLAY_KIMI_MODEL` | `kimi-k2.6` | Default Kimi model ID |
| `ROLEPLAY_GLM_MODEL` | `glm-5.2` | Default GLM model ID |
| `ROLEPLAY_PROVIDER_MODELS` | `{}` | JSON provider-specific Kimi/GLM IDs |
| `ROLEPLAY_COMPACT_TRIGGER_TOKENS` | `12000` | Ask model about compaction |
| `ROLEPLAY_HARD_INPUT_TOKENS` | `24000` | Require compaction or reject |
| `ROLEPLAY_MEMORY_TARGET_TOKENS` | `8000` | Compaction target |
| `ROLEPLAY_KEEP_RECENT_MESSAGES` | `12` | Raw recent history retained |
| `ROLEPLAY_DEFAULT_MAX_OUTPUT_TOKENS` | `900` | Smart output-budget baseline |
| `ROLEPLAY_MAX_OUTPUT_TOKENS` | `2048` | Per-turn output ceiling |
| `ROLEPLAY_MAX_REQUEST_BYTES` | `1048576` | Bounded JSON ingress |
| `ROLEPLAY_MAX_STORED_BYTES` | `64000` | Recent-message storage budget |
| `ROLEPLAY_COMPACTION_MAX_TOKENS` | `1200` | Digest output ceiling |
| `ROLEPLAY_UPSTREAM_HEADER_TIMEOUT_MS` | `90000` | Header wait before fail-closed abort |
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
