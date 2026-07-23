# Cloudflare Deployment

## Supported Runtime

The supported Cloudflare target is a hybrid Worker plus Container deployment. Most routes need Flask, normal Python packages, SQLite file access, and Gunicorn, so they run in the Container. Native LinkAPI traffic under `/linkapi/*` and Codex Everywhere OpenAI traffic under `/codex-easy/*` take direct Worker fast paths. Kimi model discovery is Worker-local; valid Kimi chat is authenticated at the edge and streamed through the Container because Kimi's edge rejects Worker-origin egress.

`wrangler.jsonc` deploys:

- Worker entry: `cloudflare-worker.mjs`
- Container class: `MultiLLMProxyContainer`
- Container image: `Dockerfile`
- Durable Object binding: `MULTILLM_PROXY_CONTAINER`
- Container instance count: `max_instances=1`
- Observability: enabled

The Worker routes Container-backed app traffic to the named `primary` container. Keeping one container instance avoids stale auth/model state from multiple Python worker processes until durable storage is introduced.

## Codex Everywhere Worker Fast Path

Configure the preferred upstream credential as a Worker secret. The existing `CODEX_API_KEY` secret name is supported as a fallback alias.

```bash
npx wrangler secret put CODEX_EASY_API_KEY
```

The upstream origin is fixed to `https://codex-easy.ai`. If a client appends `/v1`, configure `$PROXY_BASE_URL/codex-easy`; if it expects `/v1` in the configured base, use `$PROXY_BASE_URL/codex-easy/v1`.

| Operation | Direct Worker route | Caller credential |
| --- | --- | --- |
| Key-group model catalog | `/codex-easy/v1/models` | `Authorization: Bearer $ADMIN_API_KEY` |
| OpenAI Responses | `/codex-easy/v1/responses` | `Authorization: Bearer $ADMIN_API_KEY` |
| Chat Completions | `/codex-easy/v1/chat/completions` | `Authorization: Bearer $ADMIN_API_KEY` |
| Images | `/codex-easy/v1/images/*` | `Authorization: Bearer $ADMIN_API_KEY` |

The fast path accepts only the bootstrap `ADMIN_API_KEY` and replaces it with `CODEX_EASY_API_KEY` or its alias before contacting Codex Everywhere. It bypasses Flask dashboard-user authentication, application-level request-size checks, RPM/TPM/daily limits, Flask request/rate-limit accounting, and request metrics. Use the Container-backed `/v1/responses` or `/v1/chat/completions` route with a `codex-easy:<model>` model ID when those controls are required.

Catalog results are specific to the API-key group, so discover current model IDs through `/codex-easy/v1/models`. Image routes work only for image-generation key groups. The Worker preserves raw JSON, SSE, binary, and multipart bodies. On the Codex Everywhere and LinkAPI raw OpenAI fast paths, it retains a Responses `prompt_cache_key` and forwards Chat's `X-Grok-Conv-Id`. For Grok requests, [xAI recommends](https://docs.x.ai/developers/advanced-api-usage/prompt-caching/maximizing-cache-hits) these fields for cache routing, but neither the proxy nor either provider guarantees a cache hit. Generation POSTs are single-attempt; the proxy does not provide idempotency.

## Kimi Code protected routes

Configure the upstream credential as a Worker secret:

```bash
npx wrangler secret put KIMI_CODE_API_KEY
```

The upstream base is fixed to `https://api.kimi.com/coding/v1`.

| Operation | Proxy route | Execution path | Caller credential |
| --- | --- | --- | --- |
| Model catalog | `/kimi-code/v1/models` | Worker-local configured catalog | `Authorization: Bearer $ADMIN_API_KEY` |
| Chat Completions | `/kimi-code/v1/chat/completions` | Edge auth, then Container raw pass-through | `Authorization: Bearer $ADMIN_API_KEY` |

Kimi Code generation is Chat Completions only in this integration. Use `k3` on the raw route, `reasoning_effort: "max"` for K3's strongest reasoning setting, and a stable `prompt_cache_key` when the conversation prefix is stable. Cache affinity is upstream behavior and a hit is not guaranteed.

The Worker validates `ADMIN_API_KEY` before waking the Container. It serves model discovery locally; for valid chat, Flask removes the caller credential and sends `KIMI_CODE_API_KEY` upstream. The raw route bypasses unified request-size checks, RPM/TPM/daily limits, and accounting. Use `/v1/chat/completions` with model `kimi-code:k3` when those controls are needed. Requests and streams are preserved, and generation is single-attempt to avoid duplicate work and billing.

## LinkAPI Worker Fast Path

Configure the upstream credential as a Worker secret:

```bash
npx wrangler secret put LINKAPI_KEY
```

`LINKAPI_BASE_URL` is an optional, non-secret Worker variable. It defaults to `https://api.linkapi.ai` and is restricted to the Worker's allowlist of official LinkAPI hosts; arbitrary HTTPS origins are rejected. `LINKAPI_API_KEY` remains a compatibility alias, but `LINKAPI_KEY` is the preferred name.

Native routes keep their upstream protocol shape:

| Protocol | Worker route | Caller credential |
| --- | --- | --- |
| Claude Messages | `/linkapi/v1/messages` | `x-api-key: $ADMIN_API_KEY` |
| OpenAI Responses | `/linkapi/v1/responses` | `Authorization: Bearer $ADMIN_API_KEY` |
| OpenAI compatible | `/linkapi/v1/chat/completions` | `Authorization: Bearer $ADMIN_API_KEY` |
| Gemini native | `/linkapi/v1beta/models/{model}:generateContent` | Prefer `x-goog-api-key: $ADMIN_API_KEY`; `?key=$ADMIN_API_KEY` is compatibility-only |

The fast path accepts only the bootstrap `ADMIN_API_KEY` and replaces the caller credential with `LINKAPI_KEY` before contacting LinkAPI. It intentionally bypasses Flask dashboard-user authentication, application-level request-size checks, RPM/TPM/daily limits, Flask request/rate-limit accounting, and request metrics. When those controls are required, use the Container-backed `/v1/chat/completions` endpoint with a `linkapi:<model>` model ID.

Gemini clients should prefer `x-goog-api-key`. Query-string `?key=` remains available for compatibility, but it places the caller key in the URL, where clients and intermediaries may retain it, even though automatic Worker invocation logs are disabled.

The Worker streams request and response bodies without parsing or translating native SSE frames. Its raw OpenAI routes preserve Responses `prompt_cache_key` and Chat `X-Grok-Conv-Id`; for Grok, xAI recommends those shapes for cache routing, but neither this proxy nor LinkAPI guarantees a cache hit. The proxy never retries generation POSTs and does not provide idempotency, avoiding accidental duplicate generations and billing. A caller should retry only when the selected upstream protocol and endpoint explicitly document an idempotency guarantee, using its own retry policy.

## Opt-in Context Optimization

`POST /optimize/v1/chat/completions` is a Container-backed opt-in route. Normal `/v1/chat/completions`, `/v1/responses`, and provider-specific routes remain unchanged. The route uses the unified `provider:model` namespace and the normal Flask authentication, request-size, rate-limit, accounting, and metrics path.

The default `deterministic` mode makes no additional provider call. Above `optimization.trigger_input_tokens`, it can compact high-confidence older detailed image prompts while retaining the newest detailed image prompt, recent turns, system/developer instructions, multimodal exchanges, tool chains, and reasoning/thinking data. `target_input_tokens` defaults to 75% of the target provider's configured prompt limit. Reported token counts are provider-neutral byte-based estimates, not exact tokenizer usage or billing values.

`summarize` mode requires an explicit `optimization.summary_model` in `provider:model` form. When summarization is needed, it makes one additional billed and separately rate-limited summary call before the final request. Summary providers are restricted to `codex-easy`, `kimi-code`, or `linkapi` to keep transport single-attempt; calls use a bounded 45-second read timeout and two-slot per-process pool, and failed or capacity-denied summaries are not retried. Inspect `X-MultiLLM-Optimization`, `X-MultiLLM-Optimization-Mode`, `X-MultiLLM-Estimated-Input-Before`, `X-MultiLLM-Estimated-Input-After`, `X-MultiLLM-Image-Prompts-Compacted`, `X-MultiLLM-Messages-Summarized`, `X-MultiLLM-Optimization-Target-Met`, and `X-MultiLLM-Summary` headers for optimization metadata. Upstream JSON and SSE response bodies remain unchanged, and browser clients can read these headers through CORS.

The summary model must use the final model's provider by default. Eligible historical user/assistant plaintext is sent verbatim to that summary provider and can contain sensitive text. Prefer the same provider, remove secrets, and protect excluded history with `optimization.preserve_message_indices`. Cross-provider history transfer requires `optimization.allow_cross_provider_summary: true`; without that explicit disclosure opt-in the route returns `400`. The bounded digest is inserted as an untrusted historical assistant message.

Set `OPTIMIZER_MAX_REQUEST_BYTES` to control the pre-parse ingress cap (default 16 MiB) and `OPTIMIZER_SUMMARY_TIMEOUT_SECONDS` for the summary read timeout (default 45 seconds, clamped to 5-120). The transformed final body still must satisfy the selected provider's body/prompt/output limits. The target model/key, output cap, and RPM/daily capacity are checked before a paid summary.

## Important State Limitation

Cloudflare Containers have ephemeral disk when an instance sleeps or restarts. The Worker passes these default SQLite paths into the container:

- `AUTH_DB_PATH=/tmp/auth.sqlite3`
- `RATE_LIMIT_DB_PATH=/tmp/rate_limits.sqlite3`
- `MODEL_REGISTRY_DB_PATH=/tmp/model_registry.sqlite3`

This is fast and cheap for bootstrap state, but it is not durable. Created users, rotated keys, disabled model overrides, and rate-limit history can disappear after container restart. Keep `ADMIN_API_KEY` configured as the bootstrap admin key. The direct LinkAPI and Codex Everywhere fast paths intentionally authenticate against this bootstrap key because they do not wake or query the Container's SQLite database.

Use one of these architectures before relying on durable app state:

- Move Python state to an external DB reachable from the container.
- Port the small auth/model/rate-limit state layer to Cloudflare D1 or Durable Object storage.
- Keep Cloudflare as the Worker/container edge and run durable state on another managed backend.

## Required Secrets

```bash
npx wrangler secret put ADMIN_API_KEY
npx wrangler secret put FLASK_SECRET_KEY
npx wrangler secret put JWT_SECRET
```

Provider secrets are optional and should be set only when used:

```bash
npx wrangler secret put OPENAI_API_KEY
npx wrangler secret put OPENROUTER_API_KEY
npx wrangler secret put OPENCODE_GO_API_KEY
npx wrangler secret put CODEX_EASY_API_KEY
npx wrangler secret put KIMI_CODE_API_KEY
npx wrangler secret put LINKAPI_KEY
npx wrangler secret put NANOGPT_API_KEY
npx wrangler secret put NAVYAI_API_KEY
npx wrangler secret put GEMINI_API_KEY
npx wrangler secret put GROQ_API_KEY_1
npx wrangler secret put CHUTES_API_TOKEN
```

For Vertex-style Google auth:

```bash
npx wrangler secret put GOOGLE_APPLICATION_CREDENTIALS_JSON
npx wrangler secret put PROJECT_ID
npx wrangler secret put LOCATION
npx wrangler secret put GOOGLE_ENDPOINT
```

Do not place API keys in `wrangler.jsonc` `vars`. Use Worker secrets.

## Deploy Steps

```bash
npm ci
python scripts/validate_sqlite_schema.py
python scripts/check_static_secrets.py
python -m pytest -q
node --test tests/test_cloudflare_worker.mjs
npx wrangler deploy --dry-run
npx wrangler deploy
```

For a one-shot full rollout of a changed container image:

```bash
npx wrangler deploy --containers-rollout immediate
```

## Runtime Tuning

Defaults:

```bash
GUNICORN_WORKERS=1
GUNICORN_THREADS=8
GUNICORN_TIMEOUT=120
GUNICORN_GRACEFUL_TIMEOUT=30
```

Increase workers or container instances only after replacing process-local auth/model caches with a durable read-through store.

## Rollback

Use Cloudflare Workers rollback or redeploy a previous Git revision. Because the SQLite files are ephemeral, there is no durable SQLite rollback unless you later add an external database or D1 migration workflow.

## Sources

- Cloudflare Containers overview: https://developers.cloudflare.com/containers/
- Cloudflare Containers lifecycle and ephemeral disk: https://developers.cloudflare.com/containers/platform-details/architecture/
- Cloudflare Containers environment variables: https://developers.cloudflare.com/containers/platform-details/environment-variables/
- Cloudflare Workers secrets: https://developers.cloudflare.com/workers/configuration/secrets/
- Cloudflare database connectivity: https://developers.cloudflare.com/workers/databases/connecting-to-databases/
