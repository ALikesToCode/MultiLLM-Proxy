# LinkAPI and Cloudflare Optimization Implementation Plan

> **For maintainers:** Execute each task test-first and keep each completed slice in an independent, reviewable commit.

**Goal:** Integrate LinkAPI across the Worker and Flask surfaces while reducing proxy latency, Container wakeups, request buffering, duplicate-billing risk, and noisy observability costs.

**Architecture:** A raw `/linkapi/*` Cloudflare Worker fast path preserves LinkAPI's native Claude, Gemini, and OpenAI protocols. Flask keeps a compatibility/control-plane implementation for existing dashboard and unified routes. Existing providers are unchanged.

**Tech Stack:** Cloudflare Workers and Containers, JavaScript Web APIs, Wrangler, Python 3.12, Flask, Requests, pytest, and Node's built-in test runner.

---

## Task 1: Register LinkAPI in the Python control plane

**Files:**

- Create: `tests/test_linkapi_provider.py`
- Modify: `config.py`
- Modify: `services/auth_service.py`
- Modify: `services/provider_adapters.py`
- Modify: `services/model_registry.py`
- Modify: `.env.example`

1. Add failing tests for provider metadata, `LINKAPI_KEY` and `LINKAPI_API_KEY` alias resolution, dynamic `linkapi:model` acceptance, and safe defaults.
2. Run the focused tests and confirm they fail for the missing provider.
3. Implement the smallest registration and auth-alias changes.
4. Run the focused tests and adjacent provider/auth/model tests.
5. Review the staged diff and commit only this provider-registration slice.

## Task 2: Preserve native LinkAPI behavior in Flask

**Files:**

- Modify: `tests/test_linkapi_provider.py`
- Modify: `tests/test_route_helpers.py`
- Modify: `tests/test_raw_passthrough.py`
- Modify: `tests/test_unified_api.py`
- Modify: `services/proxy_service.py`
- Modify: `route_helpers.py`
- Modify: `routes/proxy.py`
- Modify: `routes/unified.py`

1. Add failing tests for Claude `x-api-key`, Gemini query-key replacement, OpenAI Bearer auth, native client proxy auth, native SSE pass-through, and LinkAPI Responses forwarding.
2. Confirm the new tests fail because the current catch-all injects Bearer auth and normalizes streams.
3. Implement path-sensitive upstream auth, sanitized query forwarding, and raw response streaming only for LinkAPI.
4. Ensure generation POSTs remain single-attempt and native event types/status codes survive unchanged.
5. Run focused route/transport/streaming tests, inspect the staged diff, and commit this transport slice.

## Task 3: Add the Worker-native LinkAPI fast path

**Files:**

- Modify: `tests/test_cloudflare_worker.mjs`
- Modify: `cloudflare-worker.mjs`
- Modify: `wrangler.jsonc`

1. Add failing Worker tests for all native caller auth styles, secret replacement, exact path/query mapping, missing-key errors, CORS, and byte-for-byte OpenAI/Claude/Gemini SSE.
2. Confirm the focused Node tests fail before production changes.
3. Implement `/linkapi/*` before Container routing, with a configurable trusted LinkAPI base URL and explicit header allowlists.
4. Stream request and response bodies and propagate abort signals; do not parse or retry generation payloads.
5. Add `LINKAPI_KEY` to Container env forwarding so Flask fallback remains functional.
6. Run the complete Worker test file, inspect the staged diff, and commit the fast-path slice.

## Task 4: Optimize safe Cloudflare Container forwarding

**Files:**

- Modify: `tests/test_cloudflare_worker.mjs`
- Modify: `cloudflare-worker.mjs`
- Modify: `wrangler.jsonc`
- Modify: `scripts/cloudflare-entrypoint.sh`

1. Add failing tests proving ordinary requests are streamed, the explicit startup RPC is absent, cancellation survives reconstruction, readiness checks the app, and Container failure returns 503.
2. Confirm the tests expose the existing buffering and redundant startup call.
3. Use `container.fetch()` directly, remove full-body buffering, enable request-signal compatibility, and keep error logs while removing routine secret-presence/access logs.
4. Configure conservative observability sampling using the current Wrangler schema.
5. Run Worker tests, configuration validation that does not build or deploy, and the relevant shell/static checks.
6. Inspect the staged diff and commit only the platform optimization slice.

## Task 5: Expose and document LinkAPI

**Files:**

- Modify: `static/js/dashboard.js`
- Modify: `routes/core.py`
- Modify: `README.md`
- Modify: `docs/deployment-cloudflare.md`
- Modify: `docs/cloudflare-containers.md`

1. Add focused metadata/documentation assertions if the repository has an established test location.
2. Add LinkAPI to the dashboard/provider descriptions and document native Worker URLs for Claude, Gemini, Responses, and OpenAI-compatible clients.
3. Document `LINKAPI_KEY`, optional `LINKAPI_BASE_URL`, proxy-auth conventions, native-stream guarantees, and the no-automatic-retry policy.
4. Run focused tests and documentation/static checks.
5. Inspect the staged diff and commit only the user-facing documentation slice.

## Task 6: Review and verify

1. Run specification-compliance review against the design and this plan.
2. Run a separate code-quality/security review and address verified findings in their owning commits.
3. Run the full Python test suite, full Worker tests, lint/type checks, static secret scan, and SQLite schema validation.
4. Confirm no `build` or `dev` command was invoked and report any verification command unavailable in the environment.

## Task 7: Configure and release

1. Confirm the working tree contains only intended changes and the configured Git author is the user's identity.
2. Authenticate Wrangler if necessary.
3. Upload `LINKAPI_KEY` from the ignored local `.env` without printing it.
4. Because this repository forbids the agent from running builds, ask the user to run the required Container build/deploy command, or obtain explicit direction that the deployment-triggered image build should proceed.
5. Verify the deployed liveness/readiness endpoints and an authenticated, non-generating LinkAPI model-list route without exposing either key.
6. Push all logical commits with the repository's configured Git identity and verify the remote branch contains them.
