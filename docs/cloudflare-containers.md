# Deploying MultiLLM-Proxy to Cloudflare Containers

This repo uses a hybrid Cloudflare Worker plus Container deployment. The Worker serves health checks, native LinkAPI traffic, Codex Everywhere OpenAI traffic, and Kimi Code OpenAI-compatible traffic directly; the Flask proxy handles the remaining routes in a Container.

## Why Containers, not Python Workers

Cloudflare's Python Workers runtime runs on Pyodide. Cloudflare's docs note that `threading`, `multiprocessing`, and `sockets` are not functional there. This app uses:

- Flask and WSGI-style request handling
- `requests` for upstream provider calls
- threaded execution and SSE streaming
- service-account JSON support for the `googleai` provider

That makes Cloudflare Containers the safer target for the Python application. `/linkapi/*`, `/codex-easy/*`, and `/kimi-code/*` are raw Worker fast paths, so their provider-native traffic does not wake the Container.

## Prerequisites

1. The target Cloudflare account must have the Workers Paid plan because Containers are only available there.
2. Authenticate Wrangler against the student roll-number account:

```bash
npx wrangler login
```

3. Install the JavaScript dependencies used by the Worker:

```bash
npm ci
```

## Secrets and variables

Wrangler `vars` in `wrangler.jsonc` already set:

- `FLASK_ENV=production`
- `SERVER_HOST=0.0.0.0`
- `SERVER_PORT=8080`
- `APP_NAME=MultiLLM Proxy`

Set secrets for anything sensitive:

```bash
npx wrangler secret put ADMIN_API_KEY
npx wrangler secret put FLASK_SECRET_KEY
npx wrangler secret put JWT_SECRET
npx wrangler secret put CODEX_EASY_API_KEY
npx wrangler secret put KIMI_CODE_API_KEY
npx wrangler secret put LINKAPI_KEY
npx wrangler secret put GEMINI_API_KEY
npx wrangler secret put OPENAI_API_KEY
npx wrangler secret put OPENROUTER_API_KEY
```

Set only the providers you actually use. The Worker forwards these directly into the container. It also forwards numbered `GROQ_API_KEY_N` secrets automatically.

`CODEX_EASY_API_KEY` is the preferred Codex Everywhere secret; `CODEX_API_KEY` remains a fallback alias. Both the Worker and Flask always use the fixed upstream origin `https://codex-easy.ai`.

### Codex Everywhere OpenAI routes

Use `$PROXY_BASE_URL/codex-easy` when the client appends `/v1` itself. Use `$PROXY_BASE_URL/codex-easy/v1` when the client expects its configured base URL to include `/v1` already.

| Operation | Direct Worker route | Caller authentication |
| --- | --- | --- |
| Key-group model catalog | `/codex-easy/v1/models` | `Authorization: Bearer $ADMIN_API_KEY` |
| OpenAI Responses | `/codex-easy/v1/responses` | `Authorization: Bearer $ADMIN_API_KEY` |
| Chat Completions | `/codex-easy/v1/chat/completions` | `Authorization: Bearer $ADMIN_API_KEY` |
| Images | `/codex-easy/v1/images/*` | `Authorization: Bearer $ADMIN_API_KEY` |

The Worker authenticates direct callers only against `ADMIN_API_KEY`, removes that caller credential, and sends `CODEX_EASY_API_KEY` or its alias upstream. These routes bypass Flask dashboard-user authentication, application-level request-size checks, RPM/TPM/daily limits, Flask request/rate-limit accounting, and request metrics. Use the Container-backed `/v1/responses` or `/v1/chat/completions` route with a `codex-easy:<model>` model ID when those controls are required.

The model catalog is API-key-group-specific; query `/codex-easy/v1/models` instead of relying on a hard-coded catalog. `/v1/images/*` works only for image-generation key groups. Raw request and response bytes are preserved for JSON, SSE, binary images, and multipart bodies.

On the Codex Everywhere and LinkAPI raw OpenAI fast paths, a Responses `prompt_cache_key` remains in the untouched body and the Chat `X-Grok-Conv-Id` header is forwarded. For Grok requests, [xAI recommends](https://docs.x.ai/developers/advanced-api-usage/prompt-caching/maximizing-cache-hits) those fields with a stable conversation ID to improve cache routing. They do not guarantee a cache hit; caching remains upstream behavior and stable request prefixes still matter. Generation POSTs are single-attempt, and this proxy does not provide idempotency.

### Kimi Code OpenAI-compatible routes

Set `KIMI_CODE_API_KEY` as a Worker secret. The upstream base is fixed to `https://api.kimi.com/coding/v1`.

| Operation | Direct Worker route | Caller authentication |
| --- | --- | --- |
| Model catalog | `/kimi-code/v1/models` | `Authorization: Bearer $ADMIN_API_KEY` |
| Chat Completions | `/kimi-code/v1/chat/completions` | `Authorization: Bearer $ADMIN_API_KEY` |

Kimi Code generation is Chat Completions only in this integration. Use model `k3` on the direct route. Send `reasoning_effort: "max"` for K3's strongest reasoning setting, and keep `prompt_cache_key` stable for stable conversation prefixes when seeking upstream cache affinity. Cache hits are not guaranteed.

The Worker authenticates the caller with `ADMIN_API_KEY`, replaces it with `KIMI_CODE_API_KEY`, and preserves the OpenAI-compatible request/response stream. The direct route bypasses Flask user authentication, request-size checks, rate limits, accounting, and metrics. Use the Container-backed `/v1/chat/completions` route with model `kimi-code:k3` when those controls are required. Chat generation is single-attempt to avoid duplicated work and billing.

`LINKAPI_KEY` is used both by the direct Worker fast path and the Container fallback. `LINKAPI_API_KEY` is supported as an alias, but `LINKAPI_KEY` is preferred. The optional, non-secret `LINKAPI_BASE_URL` variable defaults to `https://api.linkapi.ai` and is restricted to the Worker's allowlist of official LinkAPI hosts; arbitrary HTTPS origins are rejected.

### LinkAPI native routes

Use the deployed Worker URL as the base and keep the native path after `/linkapi`:

| Protocol | Route | Caller authentication |
| --- | --- | --- |
| Claude Messages | `/linkapi/v1/messages` | `x-api-key: $ADMIN_API_KEY` and `anthropic-version` |
| OpenAI Responses | `/linkapi/v1/responses` | `Authorization: Bearer $ADMIN_API_KEY` |
| OpenAI compatible | `/linkapi/v1/chat/completions` | `Authorization: Bearer $ADMIN_API_KEY` |
| Gemini native | `/linkapi/v1beta/models/{model}:generateContent` | Prefer `x-goog-api-key: $ADMIN_API_KEY`; `?key=$ADMIN_API_KEY` is compatibility-only |

These direct routes authenticate only with `ADMIN_API_KEY`. They intentionally bypass Flask dashboard-user authentication, application-level request-size checks, RPM/TPM/daily limits, Flask request/rate-limit accounting, and request metrics. The Worker removes the caller credential and sends `LINKAPI_KEY` upstream. When the Flask controls are required, use the Container-backed `/v1/chat/completions` endpoint with a `linkapi:<model>` model ID.

Gemini clients should prefer `x-goog-api-key`. Query-string `?key=` remains available for compatibility, but it places the caller key in the URL, where clients and intermediaries may retain it, even though automatic Worker invocation logs are disabled.

Request and response bodies are streamed without parsing or changing native SSE event frames. The raw OpenAI routes preserve Responses `prompt_cache_key` and Chat `X-Grok-Conv-Id`; for Grok, xAI recommends those shapes for cache routing, but neither this proxy nor LinkAPI guarantees a cache hit. Generation POSTs are single-attempt: the proxy never retries them and does not provide idempotency, because a retry can duplicate upstream work and billing. A caller should retry only when the selected upstream protocol and endpoint explicitly document an idempotency guarantee.

### Opt-in context optimization

`POST /optimize/v1/chat/completions` is Container-backed and uses the unified model namespace, authentication, request limits, rate limits, accounting, and metrics. It is opt-in: the normal `/v1/chat/completions`, `/v1/responses`, and provider-specific routes never rewrite context.

The default `deterministic` mode does not call another model. Once the request exceeds `optimization.trigger_input_tokens`, it can replace older high-confidence detailed image prompts while retaining the newest detailed image prompt and safety-critical structures such as system/developer messages, recent turns, media exchanges, tool chains, and reasoning/thinking blocks. `target_input_tokens` defaults to 75% of the selected provider's configured prompt limit; both token counts are provider-neutral byte-based estimates rather than exact tokenizer or billing usage.

`summarize` mode requires `optimization.summary_model` in `provider:model` form. If safe older plain-text history must be condensed, the route makes exactly one additional billed and separately rate-limited summary call. One-attempt summary transport is limited to `codex-easy`, `kimi-code`, and `linkapi`; calls use a bounded 45-second read timeout and two-slot per-process pool, and failure or local saturation falls back without retry. The response body and SSE bytes remain upstream-native, while `X-MultiLLM-Optimization*`, `X-MultiLLM-Estimated-Input-*`, `X-MultiLLM-Image-Prompts-Compacted`, `X-MultiLLM-Messages-Summarized`, and `X-MultiLLM-Summary` headers report what happened and are exposed through CORS.

Summary models are same-provider by default. Eligible historical user/assistant plaintext is transmitted verbatim to the selected summary provider, so it may contain sensitive text. Prefer the same provider, remove secrets, and use `preserve_message_indices` for history that must stay out of the summary. Cross-provider transfer requires the explicit `optimization.allow_cross_provider_summary: true` disclosure opt-in; otherwise the request returns `400`. The digest is inserted as an untrusted historical assistant message.

`OPTIMIZER_MAX_REQUEST_BYTES` controls the pre-parse optimizer ingress cap (16 MiB by default), while the transformed final body must still fit the selected provider's `MAX_REQUEST_BYTES`. `OPTIMIZER_SUMMARY_TIMEOUT_SECONDS` defaults to 45 seconds and is clamped to 5-120 seconds. The target model/key, output cap, and RPM/daily capacity are checked before a paid summary.

### Gemini vs Vertex-style Google auth

If you only use the Gemini/Gemma provider paths, set:

```bash
npx wrangler secret put GEMINI_API_KEY
```

If you also use the `googleai` provider that depends on Google Cloud auth, set:

```bash
npx wrangler secret put GOOGLE_APPLICATION_CREDENTIALS_JSON
npx wrangler secret put PROJECT_ID
npx wrangler secret put LOCATION
npx wrangler secret put GOOGLE_ENDPOINT
```

`GOOGLE_APPLICATION_CREDENTIALS_JSON` should contain the full service account JSON as a single secret value. The container entrypoint writes it to `/tmp/google-credentials.json` and sets `GOOGLE_APPLICATION_CREDENTIALS`. The app uses that JSON directly through `google-auth`; `gcloud` is only a local fallback when no service-account JSON/path is configured.

## Deploy

```bash
npx wrangler deploy
```

Wrangler will:

1. Build the container image from `Dockerfile`
2. Push it to Cloudflare
3. Deploy the Worker + Durable Object + container binding

## Runtime shape

- Worker entry: `cloudflare-worker.mjs`
- Direct Worker route: `/codex-easy/*`
- Direct Worker route: `/kimi-code/*`
- Direct Worker route: `/linkapi/*`
- Durable Object / Container class: `MultiLLMProxyContainer`
- Container port: `8080`
- Gunicorn entrypoint: `app:create_app()`
- Gunicorn default: `GUNICORN_WORKERS=1`, `GUNICORN_THREADS=8`

## Notes

- The deployment is pinned to a single named container instance (`primary`) to avoid auth/session drift from the app's in-memory state.
- `wrangler.jsonc` sets `max_instances=1` for the same reason.
- Container disk is ephemeral. The default SQLite paths use `/tmp`, so created users, model-disable overrides, and rate-limit rows are not durable after container restart. Keep `ADMIN_API_KEY` as the bootstrap credential and move state to D1/Durable Object storage or another external database before relying on dashboard-created users in production.
