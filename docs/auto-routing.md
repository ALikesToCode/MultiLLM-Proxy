# Automatic model priorities

MultiLLM exposes explicit virtual Chat Completions and image generation models
in the `auto:<name>` namespace. Each virtual model stores an ordered list of
normal `provider:model` candidates. This keeps fallback policy visible and
editable without changing any direct provider route.

Startup seeds these routes:

- `auto:glm-5.2`: `nanogpt:zai-org/glm-5.2:thinking`, `opencode:glm-5.2`,
  `navyai:glm-5.2`
- `auto:gpt-image-2.5`: `gguu:gpt-image-2.5`

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
`POST /optimize/v1/chat/completions`. The Responses API still requires an
explicit `provider:model` because its request and stream contracts differ
across providers.

## Image generation

`POST /v1/images/generations` accepts an `auto:<name>` model. Candidates are
tried in order; a candidate is skipped before any request when its provider
cannot generate images, has no configured credential, or the model is disabled
in Operations. Each candidate receives the same OpenAI Images body with its own
`provider:model` translated as a direct request would be.

```bash
curl "$PROXY_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto:gpt-image-2.5",
    "prompt": "A glass observatory at sunrise",
    "size": "2048x2048",
    "quality": "high",
    "moderation": "low",
    "response_format": "url",
    "n": 1
  }'
```

Image generation is paid, so failover follows the chat rule strictly: the next
candidate is tried only after `401`, `402`, `403`, `404` or `429`, or while the
provider's circuit is open. Those responses mean the candidate generated
nothing. A `5xx`, timeout or transport failure is returned as-is and never
repeated on another provider. Responses carry `X-MultiLLM-Auto-Route`,
`X-MultiLLM-Auto-Selected-Model`, `X-MultiLLM-Auto-Selected-Priority` and
`X-MultiLLM-Auto-Attempts`. Image edits still use a provider's native
`/<provider>/v1/images/edits` path.

`GET /v1/models` reports each automatic model's `capabilities` as
`supports_chat` and `supports_images`, true when at least one candidate can
serve that endpoint.

Live entries retain safe provider metadata rather than reducing every model to
an ID and token limits. NavyAI entries, for example, expose endpoint,
modalities, plan requirements, token multiplier, model capability flags,
description, pricing, and metadata provenance. `owned_by` continues to name the
MultiLLM routing provider; `upstream_owned_by` identifies the owner reported by
the upstream catalog. The original allowlisted fields are grouped under
`provider_metadata` as well as promoted where they do not conflict with the
OpenAI-compatible model envelope.

Vision is resolved per model, not from the provider's transport defaults.
`supports_vision` and `capabilities.supports_vision` agree: `true` means the
catalog advertises image input, `false` means explicit non-vision support, and
`null` means unknown. Image output (`supports_images`) does not establish image
input support. Clients should keep unknown models distinct from text-only ones.

**Refresh live models** also fills missing vision metadata for the official
AIHubMix and OpenCode origins. AIHubMix uses its public
[`/api/v1/models` catalog](https://aihubmix.com/api/v1/models); OpenCode uses its
provider-specific entries in [models.dev](https://models.dev/api.json).
`vision_metadata_source` identifies enrichment provenance. Comma-separated
modalities and nested `architecture.input_modalities` / `modalities.input` lists
are normalized to `input_modalities` arrays. Explicit model-level decisions win.

Enrichment matches exact IDs already returned by the primary catalog; it never
adds models, strips a `-free` suffix, copies pricing, or infers capabilities from
names. Custom gateway origins are not enriched from another service's catalog.
The public lookup sends no credentials, ignores environment authentication,
disallows redirects, and has time and size limits. Failure leaves the primary
catalog usable with unknown capabilities; a failed primary refresh retains the
previous cached catalog. Ordinary model-list and generation requests perform no
additional metadata lookup.

These flags describe published metadata, not a successful vision probe or an
account entitlement. AIHubMix's [official catalog tooling](https://github.com/AIhubmix/skills/tree/main/skills/aihubmixApi)
notes that modality tags can be inaccurate. Confirm the selected model with an
explicitly authorized image-input test before depending on it in production.

GLM-5.x uses provider-specific defaults on unified and automatic routes.
NanoGPT keeps native thinking with no injected effort. Other providers default
to maximum reasoning. Explicit `reasoning_effort` overrides are supported:
semantic `max` maps to `max` for OpenCode and NavyAI, `high` for LinkAPI, and
nested `reasoning.effort: xhigh` for OpenRouter. NanoGPT preserves literal `max`
for GLM-5.2, GLM-5.3, and GLM-5.3 Flash; GLM-5.1 and Flash Uncensored use `high`.
Values above a provider's ceiling
are clamped to that ceiling. Each fallback attempt applies its own provider's
default when the caller did not select an effort.

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
threshold. NanoGPT standard mode receives `caching: true`; subscription-only
mode omits it because NanoGPT treats that flag as PAYG provider selection.
Known cache-key transports receive a stable SHA-256-derived affinity key; Grok Chat receives its
conversation-affinity header. Providers such as NavyAI, OpenCode, and
OpenRouter keep their native request schema and rely on automatic stable-prefix
caching.

Caller-supplied `caching`, `prompt_caching`, `prompt_cache_key`, nested
`cache_control`, or `X-Grok-Conv-Id` values normally win. NanoGPT subscription
mode is the exception: MultiLLM removes PAYG provider/billing overrides and the
top-level `caching` flag so a subscription request cannot silently become a
paid route. Response headers report
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
- add any provider/model ID supported by the unified Chat or Images route;
- remove a candidate from the pending order;
- create additional virtual models such as `auto:kimi-k3`; and
- show whether each provider currently has a configured server credential.

On Cloudflare, saving writes the complete order to the `auto_routes` table of the
Worker's D1 database, so it survives Container sleep and redeploys (see
[control-plane storage](control-plane-storage.md#automatic-routes-in-d1)). If D1
cannot be read, routing keeps the last stored order or the seeded defaults, and a
save fails with 503 rather than being kept only on Container disk. Without the D1
store, saving writes to the SQLite database selected by `MODEL_REGISTRY_DB_PATH`;
deployments that place it in `/tmp` lose dashboard changes when that ephemeral
filesystem is replaced. There is no separate routing configuration file.

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

Configured image relays also refresh automatically when a catalog view is
opened, with a five-minute refresh window and a one-minute retry delay after
failure. This includes the global `/v1/models` list, `/admin/models`, the
Operations picker, and the setup guide. Other providers still use the explicit
**Refresh live models** action. Model-list refreshes do not generate images or
chat completions.

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
for the configured TTL. A `401`, `402`, `403`, or `429` invalidates that key.

Because those statuses reject the request before generation, unified Chat,
Responses, and image requests may immediately try the next configured NanoGPT
key. `X-MultiLLM-Credential-Attempts` reports how many keys were tried. An auto
route advances to the next provider only after NanoGPT's usable keys are
exhausted. Ambiguous transport and `5xx` failures are never replayed.

Direct `/nanogpt/*` routes preserve the raw gateway's single-attempt contract.
They invalidate a rejected configured key for the next request but return the
current upstream rejection unchanged.

Provider catalogs change over time. Query `/nanogpt/v1/models`,
`/opencode/v1/models`, and `/navyai/v1/models`, then enter the exact returned
IDs in the dashboard rather than assuming that similarly named models use the
same ID everywhere.
