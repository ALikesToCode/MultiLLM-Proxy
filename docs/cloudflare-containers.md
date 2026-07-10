# Deploying MultiLLM-Proxy to Cloudflare Containers

This repo uses a hybrid Cloudflare Worker plus Container deployment. The Worker serves health checks and native LinkAPI traffic directly; the Flask proxy handles the remaining routes in a Container.

## Why Containers, not Python Workers

Cloudflare's Python Workers runtime runs on Pyodide. Cloudflare's docs note that `threading`, `multiprocessing`, and `sockets` are not functional there. This app uses:

- Flask and WSGI-style request handling
- `requests` for upstream provider calls
- threaded execution and SSE streaming
- service-account JSON support for the `googleai` provider

That makes Cloudflare Containers the safer target for the Python application. LinkAPI is the exception: `/linkapi/*` is a raw Worker fast path, so native Claude, Gemini, and OpenAI traffic does not wake the Container.

## Prerequisites

1. The target Cloudflare account must have the Workers Paid plan because Containers are only available there.
2. Authenticate Wrangler against the student roll-number account:

```bash
wrangler login
```

3. Install the JavaScript dependencies used by the Worker:

```bash
pnpm install
```

## Secrets and variables

Wrangler `vars` in `wrangler.jsonc` already set:

- `FLASK_ENV=production`
- `SERVER_HOST=0.0.0.0`
- `SERVER_PORT=8080`
- `APP_NAME=MultiLLM Proxy`

Set secrets for anything sensitive:

```bash
wrangler secret put ADMIN_API_KEY
wrangler secret put FLASK_SECRET_KEY
wrangler secret put JWT_SECRET
wrangler secret put LINKAPI_KEY
wrangler secret put GEMINI_API_KEY
wrangler secret put OPENAI_API_KEY
wrangler secret put OPENROUTER_API_KEY
```

Set only the providers you actually use. The Worker forwards these directly into the container. It also forwards numbered `GROQ_API_KEY_N` secrets automatically.

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

Request and response bodies are streamed without parsing or changing native SSE event frames. Generation POSTs are single-attempt: the proxy never retries them and does not provide idempotency, because a retry can duplicate upstream work and billing. A caller should retry only when the selected upstream protocol and endpoint explicitly document an idempotency guarantee.

### Gemini vs Vertex-style Google auth

If you only use the Gemini/Gemma provider paths, set:

```bash
wrangler secret put GEMINI_API_KEY
```

If you also use the `googleai` provider that depends on Google Cloud auth, set:

```bash
wrangler secret put GOOGLE_APPLICATION_CREDENTIALS_JSON
wrangler secret put PROJECT_ID
wrangler secret put LOCATION
wrangler secret put GOOGLE_ENDPOINT
```

`GOOGLE_APPLICATION_CREDENTIALS_JSON` should contain the full service account JSON as a single secret value. The container entrypoint writes it to `/tmp/google-credentials.json` and sets `GOOGLE_APPLICATION_CREDENTIALS`. The app uses that JSON directly through `google-auth`; `gcloud` is only a local fallback when no service-account JSON/path is configured.

## Deploy

```bash
wrangler deploy
```

Wrangler will:

1. Build the container image from `Dockerfile`
2. Push it to Cloudflare
3. Deploy the Worker + Durable Object + container binding

## Runtime shape

- Worker entry: `cloudflare-worker.mjs`
- Direct Worker route: `/linkapi/*`
- Durable Object / Container class: `MultiLLMProxyContainer`
- Container port: `8080`
- Gunicorn entrypoint: `app:create_app()`
- Gunicorn default: `GUNICORN_WORKERS=1`, `GUNICORN_THREADS=8`

## Notes

- The deployment is pinned to a single named container instance (`primary`) to avoid auth/session drift from the app's in-memory state.
- `wrangler.jsonc` sets `max_instances=1` for the same reason.
- Container disk is ephemeral. The default SQLite paths use `/tmp`, so created users, model-disable overrides, and rate-limit rows are not durable after container restart. Keep `ADMIN_API_KEY` as the bootstrap credential and move state to D1/Durable Object storage or another external database before relying on dashboard-created users in production.
