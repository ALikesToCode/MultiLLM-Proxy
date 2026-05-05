# Deploying MultiLLM-Proxy to Cloudflare Containers

This repo now includes a Cloudflare Containers deployment target for the Flask proxy.

## Why Containers, not Python Workers

Cloudflare's Python Workers runtime runs on Pyodide. Cloudflare's docs note that `threading`, `multiprocessing`, and `sockets` are not functional there. This app uses:

- Flask and WSGI-style request handling
- `requests` for upstream provider calls
- threaded execution and SSE streaming
- service-account JSON support for the `googleai` provider

That makes Cloudflare Containers the safer target.

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
wrangler secret put GEMINI_API_KEY
wrangler secret put OPENAI_API_KEY
wrangler secret put OPENROUTER_API_KEY
```

Set only the providers you actually use. The Worker forwards these directly into the container. It also forwards numbered `GROQ_API_KEY_N` secrets automatically.

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
- Durable Object / Container class: `MultiLLMProxyContainer`
- Container port: `8080`
- Gunicorn entrypoint: `app:create_app()`
- Gunicorn default: `GUNICORN_WORKERS=1`, `GUNICORN_THREADS=8`

## Notes

- The deployment is pinned to a single named container instance (`primary`) to avoid auth/session drift from the app's in-memory state.
- `wrangler.jsonc` sets `max_instances=1` for the same reason.
- Container disk is ephemeral. The default SQLite paths use `/tmp`, so created users, model-disable overrides, and rate-limit rows are not durable after container restart. Keep `ADMIN_API_KEY` as the bootstrap credential and move state to D1/Durable Object storage or another external database before relying on dashboard-created users in production.
