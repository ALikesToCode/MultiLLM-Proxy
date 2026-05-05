# Database Optimization Report

## Current Stack Detected

- Framework: Flask 3 WSGI app.
- Python runtime: Docker uses Python 3.11; Vercel is pinned through `.python-version` to Python 3.12.
- Deployment targets: Vercel Python Function through `index.py`; Cloudflare Worker plus Cloudflare Containers through `cloudflare-worker.mjs`, `wrangler.jsonc`, and `Dockerfile`.
- Database layer: stdlib `sqlite3`; no ORM.
- SQLite files:
  - `AUTH_DB_PATH`, default `instance/auth.sqlite3`
  - `RATE_LIMIT_DB_PATH`, default `instance/rate_limits.sqlite3`
  - `MODEL_REGISTRY_DB_PATH`, default `instance/model_registry.sqlite3`
- Package managers: Node tooling has both npm and pnpm locks, but deployment docs use pnpm because Cloudflare scripts and prior install verification use pnpm.

## Problems Found

- SQLite connection setup was duplicated across auth, rate-limit, and model-registry services.
- Auth/model state used process-local caches while Cloudflare/Gunicorn could run multiple workers or container instances.
- Rate-limit retention cleanup deleted by `created_at`, but no `created_at` index existed.
- API-key verification used cache-resident user rows, which could accept stale rotated keys in another process.
- Model status lookup loaded the full override table for a single model check.
- `/health` was behind the dashboard auth redirect.
- The service worker cached navigations and precached `/login`, which could store authenticated HTML in browser Cache Storage.
- Cloudflare container env only set `AUTH_DB_PATH`; rate-limit and model-registry DBs fell back to `/app/instance`.
- Vercel config pinned an old Python runtime and did not make the `/tmp` SQLite behavior explicit.

## Fixes Implemented

- Added `services/sqlite_store.py` to centralize SQLite path resolution, busy timeout, foreign keys, WAL mode, and synchronous settings.
- Moved auth, rate-limit, and model-registry services onto the shared SQLite connection helper.
- Added `idx_users_api_key_prefix` for targeted auth key-prefix lookups.
- Changed API-key verification and dashboard login to read the current user row from SQLite before checking hashes.
- Added `idx_request_usage_created_at` for rate-limit retention cleanup.
- Changed `ModelRegistry.get_model_status()` to a single-row lookup.
- Added `scripts/validate_sqlite_schema.py` and `db:validate` / `db:migrate` package scripts for inline SQLite schema validation.
- Made `/health` and `/healthz` public liveness endpoints with `Cache-Control: no-store`.
- Added private `no-store` headers for authenticated dashboard/API responses and short public cache headers for static assets.
- Updated the service worker to precache only offline/static shell assets and stop caching navigations.
- Set Cloudflare container defaults for all SQLite paths under `/tmp`, defaulted `GUNICORN_WORKERS=1`, set `max_instances=1`, and enabled Wrangler observability.
- Added Vercel `/tmp` SQLite defaults when `VERCEL=1`.
- Added deployment docs for Vercel and Cloudflare.

## Environment Variables Required

Required:

```bash
ADMIN_API_KEY
FLASK_SECRET_KEY
JWT_SECRET
```

SQLite/runtime:

```bash
AUTH_DB_PATH
RATE_LIMIT_DB_PATH
MODEL_REGISTRY_DB_PATH
SQLITE_TIMEOUT_SECONDS
SQLITE_BUSY_TIMEOUT_MS
GUNICORN_WORKERS
GUNICORN_THREADS
GUNICORN_TIMEOUT
GUNICORN_GRACEFUL_TIMEOUT
```

Rate limits:

```bash
RATE_LIMIT_ENABLED
RATE_LIMIT_RPM
RATE_LIMIT_TPM
DAILY_REQUEST_LIMIT
MAX_REQUEST_BYTES
MAX_PROMPT_TOKENS
MAX_OUTPUT_TOKENS
RATE_LIMIT_USAGE_RETENTION_SECONDS
```

Provider keys remain optional and server-side only.

## Migration Commands

Validate schema creation on temporary SQLite files:

```bash
python scripts/validate_sqlite_schema.py
```

Apply inline schema creation/migrations to configured local SQLite paths:

```bash
python scripts/validate_sqlite_schema.py --apply
```

The app still runs inline, non-destructive `CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ADD COLUMN`, and `CREATE INDEX IF NOT EXISTS` migrations at startup.

## Vercel Deploy Steps

```bash
pnpm install --frozen-lockfile
python scripts/validate_sqlite_schema.py
python scripts/check_static_secrets.py
python -m pytest -q
vercel deploy
vercel deploy --prod
```

Set required secrets in Vercel Project Settings. Do not rely on `/tmp` SQLite files for durable production state.

## Cloudflare Deploy Steps

```bash
pnpm install --frozen-lockfile
python scripts/validate_sqlite_schema.py
python scripts/check_static_secrets.py
python -m pytest -q
node --test tests/test_cloudflare_worker.mjs
pnpm exec wrangler deploy --dry-run
pnpm exec wrangler deploy
```

Set sensitive values with `wrangler secret put`, not `wrangler.jsonc` `vars`.

## Rollback Notes

- Code rollback: redeploy a prior Git revision on Vercel or Cloudflare.
- SQLite schema changes are additive indexes/helper tables only, except the pre-existing plaintext-key migration path. No destructive migration was added in this pass.
- To undo added indexes manually on a local SQLite file:

```sql
DROP INDEX IF EXISTS idx_users_api_key_prefix;
DROP INDEX IF EXISTS idx_request_usage_created_at;
```

## Remaining Optional Optimizations

- Move state to durable storage before production user management becomes important:
  - Cloudflare D1/Durable Object storage for Cloudflare-native state.
  - Managed Postgres with pooling/HTTP driver for Vercel and container portability.
- Add a real migration directory if the SQLite schema grows further.
- Persist dashboard metrics to a durable sink if restart-proof observability is required.
- Pick one Node package manager and remove the unused lockfile after verifying CI/deploy paths.
- Add regional placement after selecting an external database provider.

## Known Limitations

- Local SQLite is fast and cheap, but not durable on Vercel Functions or Cloudflare Containers.
- Cloudflare Python Workers are not a safe target for this Flask app; Containers remain the deployable Cloudflare architecture.
- `GUNICORN_WORKERS=1` favors correctness with process-local caches. Increase only after durable read-through state is implemented.
- Build verification was not run by the agent because repo instructions prohibit running `build` or `dev`.

## Sources Consulted

- Vercel Flask docs: https://vercel.com/docs/frameworks/backend/flask
- Vercel runtimes and filesystem docs: https://vercel.com/docs/functions/runtimes
- Vercel Python runtime docs: https://vercel.com/docs/functions/runtimes/python
- Vercel function regions: https://vercel.com/docs/functions/configuring-functions/region
- Vercel environment variables: https://vercel.com/docs/environment-variables
- Cloudflare Containers overview: https://developers.cloudflare.com/containers/
- Cloudflare Containers architecture: https://developers.cloudflare.com/containers/platform-details/architecture/
- Cloudflare Workers secrets: https://developers.cloudflare.com/workers/configuration/secrets/
- Cloudflare database connectivity: https://developers.cloudflare.com/workers/databases/connecting-to-databases/
- SQLite WAL docs: https://www.sqlite.org/wal.html
- SQLite query planner docs: https://www.sqlite.org/queryplanner.html
