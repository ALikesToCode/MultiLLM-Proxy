# Findings

## Architecture Notes
- Flask app factory in `app.py` wires auth, proxy, unified API, metrics, CSRF, and runtime secret validation.
- Cloudflare Worker in `cloudflare-worker.mjs` fronts `/health`, `/`, and direct `/opencode/*` behavior.
- Provider and streaming logic is concentrated in large modules: `services/proxy_service.py`, `routes/proxy.py`, `routes/core.py`, and `cloudflare-worker.mjs`.
- Existing test coverage is strong across auth, routing, Gemini, OpenCode, streaming cleanup, static secret scanning, and Worker behavior.

## Improvement Candidates
- Reduce repeated response-header filtering by using the existing `copy_upstream_response_headers` helper consistently.
- Improve request header preparation performance/readability in `ProxyService.prepare_headers`.
- Look for duplicated dashboard/API proxy response handling before larger refactors.
- Fix CI Worker test path: workflow still runs `node --test test_cloudflare_worker.mjs`, but the file lives at `tests/test_cloudflare_worker.mjs`.
- Refresh Gemini static model list using official current model docs and avoid advertising known shut-down preview models.
- Serve tiny root-scoped PWA files from memory to avoid unclosed file handles in tests and request lifecycles.
- Remaining cleanup candidate: SQLite ResourceWarnings in auth tests come from existing test/database lifecycle behavior and were not changed in this pass.

## External References
- Google Gemini model docs were checked before touching Gemini model IDs. The current docs list Gemini 3.1/3 preview models and Gemini 2.5 stable models, and mark older/preview models as deprecated or shut down.
