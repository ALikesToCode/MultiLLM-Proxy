# Codex Everywhere Provider Implementation Plan

> **For maintainers:** Implement each task test-first and commit each logical slice independently.

**Goal:** Add Codex Everywhere as the `codex-easy` provider across Flask and Cloudflare while preserving native OpenAI Responses, Chat Completions, model discovery, image requests, streaming, and provider smart-cache behavior.

**Architecture:** Use `https://codex-easy.ai` as the only upstream origin. A raw `/codex-easy/*` Worker fast path handles latency-sensitive traffic without waking the Container; Flask provides the same provider for local, dashboard, and unified routes. Both paths replace the proxy caller credential with the CE credential, stream bodies unchanged, reject undocumented paths, and never retry generation POSTs.

**Tech Stack:** Cloudflare Workers and Containers, JavaScript Web APIs, Wrangler, Flask, Requests, pytest, and Node's built-in test runner.

## Confirmed provider contract

- Internal/public provider ID and model prefix: `codex-easy`.
- Canonical upstream base: `https://codex-easy.ai`.
- Canonical secret: `CODEX_EASY_API_KEY`; existing `CODEX_API_KEY` remains a supported fallback alias.
- Documented routes: `/v1/models`, `/v1/responses`, `/v1/chat/completions`, and `/v1/images/*` for image-generation key groups.
- Authentication: upstream `Authorization: Bearer <CE key>`.
- Model catalogs are key-group-specific. Use dynamic model IDs and the live `/v1/models` route; do not seed examples from public pricing pages.
- CE publishes no retry/idempotency guarantee. Forward every POST exactly once, including 429/5xx and connect-timeout cases.
- Preserve request bytes so CE's Codex/OpenCode smart cache receives the client's original construction.

## Task 1: Register the provider

**Files:** `config.py`, `.env.example`, `providers/registry.py`, `services/auth_service.py`, `services/model_registry.py`, `tests/test_codex_easy_provider.py`.

1. Add failing tests for base URL, long-request timeout, `CODEX_EASY_API_KEY` precedence, `CODEX_API_KEY` fallback, dynamic models, and conservative capabilities.
2. Implement the minimum registration and normalize hyphenated provider names to `CODEX_EASY_*` for rate/size environment overrides.
3. Run focused and adjacent auth/provider/model tests, review the staged diff, and commit only registration.

## Task 2: Add raw Flask transport

**Files:** `services/proxy_service.py`, `routes/proxy.py`, `routes/unified.py`, relevant focused tests.

1. Add failing tests for raw Responses/chat SSE, multipart image requests, binary/image responses, duplicate queries with incoming `key` removed, native unified Responses, safe headers, single-attempt errors/redirects, and undocumented-path rejection.
2. Generalize the reviewed raw-provider transport policy from LinkAPI to include `codex-easy` without changing other providers.
3. Strip only the `codex-easy:` model prefix on unified routes and otherwise preserve the native payload.
4. Run focused/adjacent transport and route suites, review, and commit only Flask transport.

## Task 3: Add the Worker fast path

**Files:** `cloudflare-worker.mjs`, `wrangler.jsonc`, `tests/test_cloudflare_worker.mjs`.

1. Add failing tests for `/codex-easy/*` Container bypass, timing-safe admin authentication, missing-secret errors, caller/upstream credential separation, path restrictions, streaming/backpressure, multipart/binary data, duplicate queries, manual redirects, CORS, safe headers, and exactly one POST fetch.
2. Reuse the reviewed streaming, signal propagation, logging, response-header, and timing-safe primitives rather than adding a compatibility translation.
3. Forward both CE secret aliases into the Container and support normalized `CODEX_EASY_*` limit variables.
4. Run Worker tests, current Wrangler type generation, review, and commit only the fast path.

## Task 4: Expose and document the provider

**Files:** `proxy.py`, `static/js/api-endpoints.js`, `README.md`, `.env.example`, and Cloudflare deployment docs.

1. Add dashboard metadata and routes without a hard-coded model catalog.
2. Document OpenAI SDK, Codex, Hermes, Responses, Chat Completions, models, and conditional image endpoints.
3. State that direct Worker routes use only `ADMIN_API_KEY` and bypass Flask user authentication, request-size/rate/daily controls, and Flask usage accounting; controlled clients should use the Container-backed unified route.
4. Run metadata/static/documentation checks, review, and commit only the user-facing slice.

## Task 5: Verify and release

1. Run independent specification and quality/security review.
2. Run the complete Python and Worker suites, Ruff, mypy, static-secret scan, SQLite schema validation, Node syntax checks, Wrangler type generation, and shell syntax checks without `build` or `dev`.
3. Upload `CODEX_EASY_API_KEY` by parsing only the exact ignored `.env` `CODEX_API_KEY` assignment; never source the whole file or print the value.
4. After deployment authorization, verify unauthenticated and authenticated `/codex-easy/v1/models` behavior without making a paid generation request.
