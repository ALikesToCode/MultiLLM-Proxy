# Automatic model priorities

MultiLLM exposes explicit virtual Chat Completions models in the
`auto:<name>` namespace. Each virtual model stores an ordered list of normal
`provider:model` candidates. This keeps fallback policy visible and editable
without changing any direct provider route.

The first startup seeds this route:

1. `nanogpt:zai-org/glm-5.2:thinking`
2. `opencode:glm-5.2`
3. `navyai:glm-5.2`

Use `auto:glm-5.2` with the normal unified endpoint:

```bash
curl "$PROXY_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto:glm-5.2",
    "messages": [{"role": "user", "content": "Hello"}],
    "stream": true
  }'
```

`GET /v1/models` includes every saved virtual model with
`owned_by: multillm-auto`, built-in provider models, and IDs retained from the
last successful live provider-catalog refresh. Automatic models also work through
`POST /optimize/v1/chat/completions`. Images and the Responses API still
require an explicit `provider:model` because their request and stream
contracts differ across providers.

GLM-5.2 defaults to maximum reasoning on every unified and automatic route.
The proxy maps semantic `max` to the selected transport: OpenCode receives
`max`, NanoGPT receives `max`, NavyAI receives `xhigh`, LinkAPI receives `high`, and
OpenRouter receives nested `reasoning.effort: xhigh`. Send an explicit lower
`reasoning_effort` to reduce it; values above a provider's ceiling are clamped
to that ceiling.

Long GLM-5.2 chat contexts also receive safe adaptive preprocessing on the
normal unified route. Above 8,000 estimated input tokens, older
high-confidence `IMAGE PROMPT` blocks can be replaced while surrounding story
text, the newest full prompt, system/developer directives, recent turns, media,
tools, and reasoning data remain intact. Ordinary history is never summarized
automatically and no extra provider call is made.

| Setting | Default | Purpose |
| --- | --- | --- |
| `GLM_AUTO_OPTIMIZE` | `true` | Enable safe GLM-only preprocessing |
| `GLM_AUTO_OPTIMIZE_TRIGGER_TOKENS` | `8000` | Estimated input threshold |
| `GLM_AUTO_OPTIMIZE_KEEP_RECENT_TURNS` | `8` | Full recent user turns to retain |
| `CONTEXT_ANALYSIS_CACHE_ENABLED` | `true` | Cache prompt classification by SHA-256 |
| `CONTEXT_ANALYSIS_CACHE_TTL_SECONDS` | `300` | Process-local analysis lifetime |
| `CONTEXT_ANALYSIS_CACHE_MAX_ENTRIES` | `2048` | Bounded metadata entry count |

The analysis cache stores hashes and prompt-span offsets only. It never stores
conversation text or model responses, and it is not shared between containers.

## Provider prompt caching

Eligible unified Chat and Responses requests automatically use the selected
provider's supported prompt-cache mechanism. `PROMPT_CACHE_ENABLED=true` turns
the policy on, and `PROMPT_CACHE_MIN_TOKENS=1024` controls its estimated-input
threshold. NanoGPT Chat receives `caching: true`; known cache-key transports
receive a stable SHA-256-derived affinity key; Grok Chat receives its
conversation-affinity header. Providers such as NavyAI, OpenCode, and
OpenRouter keep their native request schema and rely on automatic stable-prefix
caching.

Caller-supplied `caching`, `prompt_caching`, `prompt_cache_key`, nested
`cache_control`, or `X-Grok-Conv-Id` values always win. Response headers report
the attempted mode through `X-MultiLLM-Prompt-Cache`,
`X-MultiLLM-Prompt-Cache-Mode`, and
`X-MultiLLM-Prompt-Cache-Estimated-Tokens`. This is upstream prompt caching,
not generated-response caching: MultiLLM never replays a stored completion and
never adds cache fields to raw provider passthrough bodies.

The authenticated `/docs` route presents the same combined catalog alongside
copyable chat and image requests, runtime credential status, native provider
paths, and the currently saved automatic priorities. `/docs.json` exposes the
credential-safe guide data to an authenticated dashboard session.

## Edit priorities in the dashboard

Sign in as an administrator and open **Operations**. The **Automatic model
priorities** panel can:

- reorder candidates with Up and Down controls;
- add any provider/model ID supported by the unified Chat route;
- remove a candidate from the pending order;
- create additional virtual models such as `auto:kimi-k3`; and
- show whether each provider currently has a configured server credential.

Saving writes the complete order to the SQLite database selected by
`MODEL_REGISTRY_DB_PATH`. There is no separate routing configuration file.
Container or serverless deployments that place this database in `/tmp` lose
dashboard changes when that ephemeral filesystem is replaced; use durable
storage before relying on saved priorities in production.

The authenticated dashboard API is `GET` and `PUT /admin/auto-routes`. A PUT
body has this shape:

```json
{
  "route_id": "auto:glm-5.2",
  "candidates": [
    "nanogpt:zai-org/glm-5.2:thinking",
    "opencode:glm-5.2",
    "navyai:glm-5.2"
  ]
}
```

The browser sends the normal session cookie and CSRF token. The API returns
configuration state only and never returns provider keys.

The dashboard includes the exact environment-variable names for every provider.
For the default priority route, a local setup can use:

```dotenv
OPENCODE_GO_API_KEY=your-key
NANOGPT_API_KEY=your-first-key
NANOGPT_API_KEY_1=your-second-key
NAVYAI_API_KEY=your-key
```

Restart the proxy after changing its environment. Hosted deployments require
the same values in their runtime secret store; changing a repository `.env`
file does not update an already deployed Worker or container.

**Refresh live models** calls `POST /admin/auto-routes/catalog`. It performs
read-only model-list requests for configured providers and public NavyAI or
OpenRouter catalogs, caches successful model metadata in
`MODEL_REGISTRY_DB_PATH`, and preserves the last good catalog when a provider is
unavailable. The searchable dashboard combines live IDs and provider-specific
context/output limits with built-in IDs and models already referenced by saved
routes. A shared model name never inherits limits from another gateway.
Provider keys and upstream error bodies are never returned to the browser.

## Failover boundary

MultiLLM advances to the next locally available candidate only when the
current attempt returns a definite pre-generation availability rejection:

- `401` or `403`: provider credential rejected;
- `402`: provider balance or payment requirement prevents generation;
- `404`: provider/model unavailable;
- `429`: provider rate limit reached; or
- a local `503` marked with `X-MultiLLM-Circuit-State: open` or `half_open`,
  which means no upstream request was sent.

Disabled models and providers without a configured credential are skipped
before transport. The first response outside this list is returned unchanged,
including `400`, `408`, generic `5xx`, network failures, and successful stream
starts. Those outcomes may be ambiguous after a paid generation began, so the
proxy does not replay them through another provider. It never fabricates a
successful fallback body.

Every selected response includes:

- `X-MultiLLM-Auto-Route`
- `X-MultiLLM-Auto-Selected-Model`
- `X-MultiLLM-Auto-Attempts`
- `X-MultiLLM-Auto-Selected-Priority`

The standard `X-MultiLLM-Provider`, `X-MultiLLM-Model`, and
`X-MultiLLM-Route-Decision` headers report the actual selected candidate and
whether it was the primary route or a failover.

## NanoGPT key pools

Unified NanoGPT Chat, Responses, and image requests use the same configured
key pool as direct `/nanogpt/*` routes. The process checks the read-only model
catalog when more than one key is configured and retains the first working key
for the configured TTL. A `401`, `403`, or `429` invalidates that key for a
later request.

An automatic request does not replay the same paid generation against another
NanoGPT key. After a NanoGPT rejection it advances to the next provider in the
virtual model. A `402` insufficient-balance response also advances without
replaying NanoGPT. A later request can select another working NanoGPT key.

Provider catalogs change over time. Query `/nanogpt/v1/models`,
`/opencode/v1/models`, and `/navyai/v1/models`, then enter the exact returned
IDs in the dashboard rather than assuming that similarly named models use the
same ID everywhere.
