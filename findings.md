# Findings & Decisions

## Requirements
- Deploy the service on Cloudflare.
- Choose Cloudflare Workers or Cloudflare Containers based on what best fits the service.
- Use the student's roll-number Cloudflare account.
- Follow repo instruction not to run build or dev locally.

## Research Findings
- Initial repo scan shows only `package.json` and `README.md` at the root, so the runtime shape is not yet known.
- `package.json` only contains Tailwind CSS build/watch scripts and no runtime or deploy scripts.
- `README.md` describes a Python service started with `python app.py`, using `.env` and `requirements.txt`, which do not appear in the initial root scan.
- Full repo scan shows this is a Flask application (`app.py`, `wsgi.py`, `requirements.txt`, templates/static assets) plus a legacy Vercel adapter (`index.py`, `vercel.json`).
- `app.py` runs a threaded Flask server and exposes multiple streaming endpoints using `Response(..., mimetype='text/event-stream')`.
- `services/proxy_service.py` depends on `requests`, `ThreadPoolExecutor`, and `threading`; it also shells out to `gcloud` for one Google-auth flow.
- Cloudflare Workers Python docs state Workers run on Pyodide and that `threading`, `multiprocessing`, and `sockets` are present but not functional.
- Cloudflare Containers docs recommend the `Container` class for long-lived runtimes and show direct request forwarding with `env.MY_CONTAINER.getByName(\"...\").fetch(request)`.
- Cloudflare Wrangler configuration docs show Containers require three linked config pieces: `containers`, `durable_objects.bindings`, and `migrations`.
- Cloudflare Containers env var docs confirm Worker secrets can be passed into containers via `envVars`, including per-instance values through `startAndWaitForPorts()`.
- Cloudflare Containers beta docs state scaling is currently manual and instances are not autoscaled or load-balanced automatically.
- `wrangler whoami` succeeded against the student account `development@sciencestudent.8shield.net`, and the token includes `containers (write)`.
- `pnpm install` completed successfully and produced local deployment dependencies plus `pnpm-lock.yaml`.
- A safe `wrangler deploy --dry-run` reached the container image build stage, then failed locally because Docker on this machine does not have the `buildx` plugin; Wrangler expects Docker support for `--load`.
- Installing Docker `buildx` in the user CLI plugin directory fixed the local Cloudflare container build path.
- A full `wrangler deploy --secrets-file /tmp/multillm-proxy-cloudflare-secrets.json --containers-rollout immediate` succeeded for account `9b0a1524e478000ec9b3ff2da6104d81`.
- The deployed Worker URL is `https://multillm-proxy.cserules.workers.dev`.
- External verification confirms `/` redirects to `/login` and `/login` returns the Flask login page over Cloudflare.

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| Delay platform choice until after inspecting package scripts and docs | Workers vs Containers depends on runtime, network/socket use, and start model |
| Use Cloudflare Containers instead of Python Workers | The app depends on Flask, `requests`, SSE streaming, and `threading`, which do not fit Pyodide Workers well |
| Forward Worker secrets into the container at startup | Cloudflare’s recommended secret flow for Containers maps cleanly to this app’s many provider API keys |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| Docker lacks `buildx`, so Wrangler cannot build the Cloudflare container image locally | Need to install Docker buildx or use a machine that already has it |
| Guardrails blocked automatic use of repo-local `.env` secrets for deployment | User later approved secret upload, and deployment proceeded |

## Resources
- Repo root: `/home/mysterious/storage/github/MultiLLM-Proxy`
- `package.json`
- `README.md`
- Cloudflare Python Workers stdlib/runtime docs: https://developers.cloudflare.com/workers/languages/python/stdlib/
- Cloudflare Containers package docs: https://developers.cloudflare.com/containers/container-package/
- Cloudflare Containers env vars and secrets docs: https://developers.cloudflare.com/containers/examples/env-vars-and-secrets/
- Cloudflare Wrangler containers configuration docs: https://developers.cloudflare.com/workers/wrangler/configuration/
- Cloudflare Containers beta info: https://developers.cloudflare.com/containers/beta-info/
- Deployed URL: https://multillm-proxy.cserules.workers.dev

## Visual/Browser Findings
- None yet

---
*Update this file after every 2 view/browser/search operations*
*This prevents visual information from being lost*
