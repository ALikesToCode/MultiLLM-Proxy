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
`POST /optimize/v1/chat/completions`, `POST /v1/responses` and the Anthropic
`POST /v1/messages`: those requests are translated to Chat Completions, run
through the same candidates and failover rules, and translated back, streams
included ([protocol translation](protocol-translation.md)). Features that need
server-side state, such as `previous_response_id` or built-in `web_search`,
return `400` on automatic routes.

## Image generation

`POST /v1/images/generations` accepts an `auto:<name>` model; `auto:image`,
`auto:image-fast`, `auto:gpt-image-2.5`, `auto:image-edit` and `auto:video` are seeded
([media generation](media-generation.md)), as are `auto:embed`, `auto:tts` and
`auto:stt` for embeddings, speech and transcription. Candidates are tried in order; a
candidate is skipped before any request when its provider cannot generate images,
has no configured credential, or the model is disabled in Operations. `quality`
defaults to `max`, and each candidate receives the closest settings its model
supports (quality, size or aspect ratio, and only the fields it accepts).

```bash
curl "$PROXY_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "auto:image",
    "prompt": "A glass observatory at sunrise",
    "size": "2048x2048",
    "response_format": "url",
    "n": 1
  }'
```

Any HTTP error from an image provider, `5xx` included, means it delivered no
image, so the next candidate is tried; so is a request that never connected. A
timeout or a connection dropped after the request was sent may already be billed:
it is returned with `X-MultiLLM-Transport-Failure` and never repeated on another
provider. `n` above 1 sends one request per image, each with its own failover.
Chat routes use a narrower rule, described under [Failover boundary](#failover-boundary).
Responses carry the same `X-MultiLLM-Auto-*` headers as chat. `POST /v1/images/edits`
routes the same way over candidates that accept source images; embedding, speech and
transcription routes move on only after a definite refusal (see
[media generation](media-generation.md)).

`GET /v1/models` reports each automatic model's `capabilities` as
`supports_chat`, `supports_images` and `supports_video`, true when at least one
candidate can serve that endpoint. Image and video models count only for media,
even on providers that also serve chat.

Every `/v1/models` entry carries `capabilities` as an object of flags, including
`free:*` pools and `auto:intelligence` (whose reviewed tags are in `capability_tags`).
`supports_chat` is per model: it is `false` for image and video generation models.
OpenCode models served only through the Responses or Messages protocol report
`supports_chat: true`, because unified chat translates for them; their
`api_endpoint` still names the native protocol, so an automatic route may mix
them with Chat Completions candidates. `context_window` and
`max_output_tokens` appear only when known; they are never `null`.

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

**Refresh live models** also fills metadata the provider's own catalog left
unknown, from [models.dev](https://models.dev/api.json): `context_window`,
`max_output_tokens`, image input (`input_modalities`, `supports_vision`),
`output_modalities`, `supports_tools`, `supports_reasoning`, and base-tier USD list
prices as `input_cost_per_million` and `output_cost_per_million`. Each provider
reads only the models.dev entry for the same endpoint:

| Provider | models.dev entry | Prices copied |
| --- | --- | --- |
| `openai`, `xai`, `groq`, `cerebras`, `openrouter` | same name | yes |
| `together` | `togetherai` | yes |
| `aihubmix` | `aihubmix`, after AIHubMix's own [`/api/v1/models` catalog](https://aihubmix.com/api/v1/models) (image input only) | yes |
| `opencode` on Zen (`/zen/v1`) | `opencode` | yes |
| `opencode` on Go (`/zen/go/v1`) | `opencode-go`; free Zen models use `opencode` | Go: no (subscription) |
| `nanogpt` | `nano-gpt` | no (subscription) |

Other providers (LinkAPI, Codex Easy, Kimi Code, NavyAI, image relays) and custom
origins are not enriched, because no reviewed entry describes that endpoint.
OpenRouter's `supported_parameters` list sets `supports_tools` from the upstream
catalog itself. Comma-separated modalities and nested
`architecture.input_modalities` / `modalities.input` lists are normalized to
`input_modalities` arrays.

Explicit provider values always win: an upstream limit, a capability flag (a
`null` placeholder does not count) or any upstream `pricing` object is kept, and
enrichment fills only the gaps. `metadata_provenance` maps every filled field to its source (for example
`"context_window": "https://models.dev/api.json#groq"`); `vision_metadata_source`
remains for image input. A model marked `supports_tools: false` reports
`capabilities.supports_tools: false`. Upstream `pricing` keeps the provider's own
shape (OpenRouter prices per token); the `*_cost_per_million` fields are models.dev
list prices, which ignore context tiers, caching and account discounts.

Enrichment matches exact, case-sensitive IDs already returned by the primary
catalog; it never adds models, strips a `-free` suffix, borrows another provider's
entry, or infers capabilities from names. The public lookup sends no credentials,
ignores environment authentication, disallows redirects, and has time (30 s) and
size (16 MiB) limits. Each source is read at most once an hour per process and only
a compact index is kept; after a failed read the last good copy is used for up to a
day, and without one the primary catalog stays usable with unknown fields. A failed
primary refresh retains the previous cached catalog. Ordinary model-list and
generation requests perform no additional metadata lookup.

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
not generated-response caching: it never replays a stored completion and never
adds cache fields to raw provider passthrough bodies. Replaying a completion
requires the caller's opt-in to the [response cache](#response-cache).

## Response cache

`POST /v1/chat/completions` can answer a repeated deterministic request from a
Container-local cache. It is opt-in per request, never a key default, so a
shared key never starts replaying answers unexpectedly:

```bash
curl "$PROXY_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "X-MultiLLM-Cache: on" \
  -H "Content-Type: application/json" \
  -d '{"model": "auto:glm-5.2", "temperature": 0,
       "messages": [{"role": "user", "content": "Summarize RFC 9110 in one line"}]}'
```

A request is eligible when it is not streamed, asks for one choice (`n` absent
or 1), is deterministic (`temperature` is 0 or `seed` is an integer), offers no
`tools` or `functions` unless `tool_choice` is `"none"`, and does not use
`auto:intelligence` or `routing`. The key is a SHA-256 of the API key's
identity, the path and the request body encoded as canonical JSON (sorted keys),
so an entry is never served to another key and any body change is a miss.
Request headers are not part of the key.

Authentication, scope and rate-limit checks run before a hit is served. Only a
complete `200` JSON answer is stored: every choice must end with `stop` (or an
equivalent) and carry no tool call. Errors, truncated (`length`) or filtered
answers and streams are never stored.

| Request header | Effect |
| --- | --- |
| `X-MultiLLM-Cache: on` | Serve a stored answer, or store a new one |
| `X-MultiLLM-Cache: refresh` or `Cache-Control: no-cache` | Skip the lookup and store the new answer |
| `Cache-Control: max-age=N` | Serve only an answer at most `N` seconds old |
| `Cache-Control: no-store` | No lookup and no storage |

The response carries `X-MultiLLM-Cache: hit`, `miss`, or `bypass` when the
request opted in but is not eligible; a hit also has `Age` and
`X-MultiLLM-Route-Decision: cache-hit`. Requests without the opt-in header are
unchanged and carry no cache header.

| Setting | Default | Purpose |
| --- | --- | --- |
| `RESPONSE_CACHE_ENABLED` | `true` | Honour the opt-in header at all |
| `RESPONSE_CACHE_TTL_SECONDS` | `300` | Lifetime of a stored answer (1 to 86400) |
| `RESPONSE_CACHE_MAX_ENTRIES` | `512` | Entry limit; least recently used entries go first |
| `RESPONSE_CACHE_MAX_BYTES` | `16777216` | Byte budget; one answer may use an eighth |

The cache lives in Container memory: it is lost when the Container sleeps or is
replaced and is not shared between instances. A model disabled in Operations
stops receiving new requests at once, but an answer stored earlier can be
served until its TTL ends.

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

A chat route advances to the next locally available candidate only when the
current attempt ended before any response byte reached the caller and did not
leave a generation running:

- `401` or `403`: provider credential rejected;
- `402`: provider balance or payment requirement prevents generation;
- `404`: provider/model unavailable;
- `429`: provider rate limit reached;
- a local `503` marked with `X-MultiLLM-Circuit-State: open` or `half_open`,
  which means no upstream request was sent;
- `500`, `502` or `503` returned by the upstream. The decision is made on the
  status line, before the body or any stream byte is forwarded, so the caller
  has received nothing; or
- a connection that was never established (DNS failure, refused connection or
  connect timeout), reported as `X-MultiLLM-Transport-Failure: connect`.

Disabled models and providers without a configured credential are skipped
before transport. Any other outcome is returned unchanged and never repeated on
another provider: `400` and other client errors, `408`, `504`, a read timeout or
a connection dropped after the request was sent (`X-MultiLLM-Transport-Failure:
timeout` or `interrupted`), and every successful status, including a stream that
has started. A `504` or a timeout may hide a generation that is still running
and billed upstream. A streaming request whose upstream answers with an error
status receives that status and body, not a `200` event stream, so the rule
applies to streams as well. The proxy never fabricates a successful fallback
body.

Earlier releases returned upstream `500`, `502`, `503` and connect failures to
the caller; only the first five items in the list moved on.

Every selected response includes:

- `X-MultiLLM-Auto-Route`
- `X-MultiLLM-Auto-Selected-Model`
- `X-MultiLLM-Auto-Attempts`: candidates dispatched after the credential check
- `X-MultiLLM-Auto-Selected-Priority`: the candidate's configured position
- `X-MultiLLM-Auto-Ordering`: `priority`, `health` or `health-probe`
- `X-MultiLLM-Auto-Failover-Reasons`, when another candidate was passed over:
  `model=reason` pairs such as `nanogpt:zai-org/glm-5.2:thinking=http_503` or
  `navyai:glm-5.2=skipped`

When every candidate fails, the last failure is returned with these headers.
The standard `X-MultiLLM-Provider`, `X-MultiLLM-Model`, and
`X-MultiLLM-Route-Decision` headers report the actual selected candidate.
`X-MultiLLM-Route-Decision` is `auto-primary` for the configured first
candidate, `auto-health` when health ordering put another candidate first, and
`auto-failover` after an earlier candidate was skipped or failed.

## Health-aware ordering

Candidates are tried in their configured order unless a route opts in to health
ordering. Then candidates with a recently poor success rate or much slower
responses move behind healthier ones, candidates whose provider circuit is open
go last, and the configured order remains the tiebreaker: a candidate passes the
one before it only when its score is higher by more than a margin. Scores decay
back to healthy while a candidate receives no traffic, so a provider that
recovers is tried again in its configured place.

```dotenv
AUTO_ROUTE_ORDERING=priority                    # or health, for every route
AUTO_ROUTE_ORDERING_OVERRIDES=auto:glm-5.2=health,auto:image=priority
```

The per-route override wins over the global setting. Scoring, cost weighting,
exploration, persistence in D1 and the other settings are described in
[status and health](status-and-health.md#health-aware-ordering).

## NanoGPT key pools

Unified NanoGPT Chat, Responses, and image requests use the same configured
key pool as direct `/nanogpt/*` routes. The process checks the read-only model
catalog when more than one key is configured and retains the first working key
for the configured TTL. A `401`, `402`, `403`, or `429` invalidates that key.

Because those statuses reject the request before generation, unified Chat,
Responses, and image requests may immediately try the next configured NanoGPT
key. `X-MultiLLM-Credential-Attempts` reports how many keys were tried. An auto
route advances to the next provider only after NanoGPT's usable keys are
exhausted. A `5xx` or transport failure is never retried with another NanoGPT
key; an automatic route may still move to the next provider under the
[failover boundary](#failover-boundary).

Direct `/nanogpt/*` routes preserve the raw gateway's single-attempt contract.
They invalidate a rejected configured key for the next request but return the
current upstream rejection unchanged.

Provider catalogs change over time. Query `/nanogpt/v1/models`,
`/opencode/v1/models`, and `/navyai/v1/models`, then enter the exact returned
IDs in the dashboard rather than assuming that similarly named models use the
same ID everywhere.
