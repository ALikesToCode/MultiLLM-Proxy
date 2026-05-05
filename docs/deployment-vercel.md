# Vercel Deployment

## Supported Runtime

This repo is a Flask/Python app. Vercel's current Flask support can deploy a root `app.py` or `index.py` Flask `app` as a single Python Function. This project keeps `index.py` as the configured Vercel entrypoint and uses `.python-version` to request Python 3.12.

## Important State Limitation

The app currently stores auth users, model overrides, and rate-limit rows in SQLite files. Vercel Functions have a read-only filesystem with writable `/tmp` scratch space, so `vercel.py` defaults these files to `/tmp` when `VERCEL=1`:

- `AUTH_DB_PATH=/tmp/multillm-auth.sqlite3`
- `RATE_LIMIT_DB_PATH=/tmp/multillm-rate-limits.sqlite3`
- `MODEL_REGISTRY_DB_PATH=/tmp/multillm-model-registry.sqlite3`

That keeps the function writable, but it is not durable. Use `ADMIN_API_KEY` as the bootstrap credential. Do not rely on dashboard-created users, rotated keys, disabled model overrides, or rate-limit history to survive function replacement until state is moved to external durable storage.

## Required Environment Variables

Set these in Vercel Project Settings for Production and Preview:

```bash
ADMIN_API_KEY=<strong admin bootstrap key>
FLASK_SECRET_KEY=<strong Flask session secret>
JWT_SECRET=<strong JWT secret>
```

Set only the provider secrets you use:

```bash
OPENAI_API_KEY=<optional>
OPENROUTER_API_KEY=<optional>
OPENCODE_API_KEY=<optional>
GEMINI_API_KEY=<optional>
GROQ_API_KEY_1=<optional>
CHUTES_API_TOKEN=<optional>
```

For Vertex-style Google auth:

```bash
GOOGLE_APPLICATION_CREDENTIALS_JSON=<service-account-json>
PROJECT_ID=<gcp-project>
LOCATION=<gcp-location>
GOOGLE_ENDPOINT=<google-endpoint>
```

## Deploy Steps

```bash
pnpm install --frozen-lockfile
python scripts/validate_sqlite_schema.py
python scripts/check_static_secrets.py
python -m pytest -q
vercel deploy
```

For production:

```bash
vercel deploy --prod
```

## Config Notes

- `vercel.json` routes all traffic to `index.py`.
- `functions.index.py.maxDuration` is set to `300` seconds for long provider calls and streaming.
- `excludeFiles` keeps tests, caches, docs, local DB files, and Node dependencies out of the Python Function bundle.
- `regions` is not pinned in source because there is no external database region to colocate with. If you add a managed DB, set the Vercel function region close to that DB.

## Rollback

Rollback code with Vercel's deployment rollback or redeploy a previous commit. SQLite state on `/tmp` is ephemeral; there is no Vercel-side SQLite state rollback to perform.

## Sources

- Vercel Flask docs: https://vercel.com/docs/frameworks/backend/flask
- Vercel runtimes and filesystem docs: https://vercel.com/docs/functions/runtimes
- Vercel Python runtime docs: https://vercel.com/docs/functions/runtimes/python
- Vercel function regions: https://vercel.com/docs/functions/configuring-functions/region
- Vercel environment variables: https://vercel.com/docs/environment-variables
