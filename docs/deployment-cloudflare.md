# Cloudflare Deployment

## Supported Runtime

The supported Cloudflare target is a hybrid Worker plus Container deployment. Most routes need Flask, normal Python packages, SQLite file access, and Gunicorn, so they run in the Container. Native LinkAPI traffic under `/linkapi/*` takes a direct Worker fast path to avoid a Container wakeup and preserve provider-native streaming.

`wrangler.jsonc` deploys:

- Worker entry: `cloudflare-worker.mjs`
- Container class: `MultiLLMProxyContainer`
- Container image: `Dockerfile`
- Durable Object binding: `MULTILLM_PROXY_CONTAINER`
- Container instance count: `max_instances=1`
- Observability: enabled

The Worker routes Container-backed app traffic to the named `primary` container. Keeping one container instance avoids stale auth/model state from multiple Python worker processes until durable storage is introduced.

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

The Worker streams request and response bodies without parsing or translating native SSE frames. The proxy never retries generation POSTs and does not provide idempotency, avoiding accidental duplicate generations and billing. A caller should retry only when the selected upstream protocol and endpoint explicitly document an idempotency guarantee, using its own retry policy.

## Important State Limitation

Cloudflare Containers have ephemeral disk when an instance sleeps or restarts. The Worker passes these default SQLite paths into the container:

- `AUTH_DB_PATH=/tmp/auth.sqlite3`
- `RATE_LIMIT_DB_PATH=/tmp/rate_limits.sqlite3`
- `MODEL_REGISTRY_DB_PATH=/tmp/model_registry.sqlite3`

This is fast and cheap for bootstrap state, but it is not durable. Created users, rotated keys, disabled model overrides, and rate-limit history can disappear after container restart. Keep `ADMIN_API_KEY` configured as the bootstrap admin key. The direct LinkAPI fast path intentionally authenticates against this bootstrap key because it does not wake or query the Container's SQLite database.

Use one of these architectures before relying on durable app state:

- Move Python state to an external DB reachable from the container.
- Port the small auth/model/rate-limit state layer to Cloudflare D1 or Durable Object storage.
- Keep Cloudflare as the Worker/container edge and run durable state on another managed backend.

## Required Secrets

```bash
wrangler secret put ADMIN_API_KEY
wrangler secret put FLASK_SECRET_KEY
wrangler secret put JWT_SECRET
```

Provider secrets are optional and should be set only when used:

```bash
wrangler secret put OPENAI_API_KEY
wrangler secret put OPENROUTER_API_KEY
wrangler secret put OPENCODE_API_KEY
wrangler secret put LINKAPI_KEY
wrangler secret put GEMINI_API_KEY
wrangler secret put GROQ_API_KEY_1
wrangler secret put CHUTES_API_TOKEN
```

For Vertex-style Google auth:

```bash
wrangler secret put GOOGLE_APPLICATION_CREDENTIALS_JSON
wrangler secret put PROJECT_ID
wrangler secret put LOCATION
wrangler secret put GOOGLE_ENDPOINT
```

Do not place API keys in `wrangler.jsonc` `vars`. Use Worker secrets.

## Deploy Steps

```bash
pnpm install --frozen-lockfile
python scripts/validate_sqlite_schema.py
python scripts/check_static_secrets.py
python -m pytest -q
node --test tests/test_cloudflare_worker.mjs
pnpm exec wrangler deploy --dry-run
pnpm exec wrangler deploy
```

For a one-shot full rollout of a changed container image:

```bash
pnpm exec wrangler deploy --containers-rollout immediate
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
