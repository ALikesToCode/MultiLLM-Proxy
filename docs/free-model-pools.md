# Free text and vision pools

These OpenAI-compatible routes select a configured free model and move to
another provider after quota exhaustion or an upstream availability failure.
Use `free:text` or `free:vision` on the standard `/v1/chat/completions`
endpoint. Both aliases are listed by `/v1/models`. Explicit provider models,
saved `auto:` routes, and roleplay routing retain their existing behavior.

For all account/key names and enablement settings, see the
[11-service setup checklist](free-provider-setup.md). Six additional services
are opt-in: Mistral, Workers AI, Z.ai, OrcaRouter, BazaarLink and LLM7.

| OpenAI-compatible base path | Model | Purpose |
| --- | --- | --- |
| `/v1` | `free:text` or `free:vision` | Standard endpoint; specify the alias explicitly |
| `/v1/free` | `free:text` or `free:vision` | Universal pool, selected by model |
| `/v1/free/text` | `free:text` | Text conversations; rejects image input |
| `/v1/free/vision` | `free:vision` | Image understanding with confirmed vision models |

Append `/chat/completions` for generation or `/models` for discovery. The fixed
paths supply their model if omitted, and reject a conflicting model. The
`/v1/free` path defaults to `free:text`. Vision means image **input**, not image
generation. Text requests may use vision-capable models without images.

## Setup and billing boundary

Configure provider keys through the existing secret storage. Do not put a
provider key in the client: clients send a MultiLLM proxy key with the `chat`
scope; discovery requires `models` scope. Admin keys have both.

The default pools accept only AIHubMix `-free` models, OpenCode free Zen models
with a Chat Completions endpoint, and OpenRouter `:free` variants or
`openrouter/free`. A nonzero or unparseable catalog price disqualifies a
free-labelled model. Paid aliases, subscription models, tool-only protocols and
image-output-only models do not enter these pools. Calls go to fixed official
provider origins, not custom relay URLs.

OpenRouter's [free router](https://openrouter.ai/openrouter/free) selects free
models compatible with the request, including image input. It is available as
a built-in fallback even before catalog refresh. Other discovered models use
the cached model-level capability metadata. In the dashboard, use **Refresh live
models** to populate newly advertised free vision models. Unknown image support
does not qualify for the vision pool. Discovery never sends a generation.

Groq and Gemini are different: the same model can incur charges on an upgraded
organization/project. They are **off by default** in these pools even when a key
is configured. Only after checking that the actual credentials belong to free
accounts/projects, enable them in server configuration and restart:

```dotenv
FREE_ROUTE_FREE_TIER_PROVIDERS=groq,gemini
FREE_ROUTE_PROVIDER_ORDER=groq,opencode,aihubmix,gemini,openrouter
```

This is an operator assertion, not a billing check or a per-request spending
cap. Remove the assertion before upgrading an account to paid. If you require
free-labelled models regardless of account tier, leave the first setting empty.
The seed list for the optional free tiers is Groq `qwen/qwen3.8-27b`,
`qwen/qwen3.6-27b`, `openai/gpt-oss-120b` (text), and Gemini
`gemini-3.1-flash-lite`. It deliberately does not admit every model on a paid
provider. No benchmark or universal quota is inferred from these names.

Provider ordering is server-owned and deterministic, not a measured speed
ranking. The first eligible provider wins; within a provider, the optional
free-tier seed order is used, otherwise model IDs are sorted, with
`openrouter/free` first on OpenRouter. Unconfigured and disabled models are
skipped. Reordering cannot admit a paid candidate.

## Quota and failure behavior

- `429` pauses the provider across **both pools**, so switching to another model
  on the same account does not immediately hit the same quota again.
- `Retry-After` accepts seconds or an HTTP date. Exhausted Groq-style request and
  token counters use their reset durations; the longest applicable wait wins.
  A successful response with zero remaining quota also pauses that provider for
  the next request. Unusable headers use a 60-second fallback, not a guessed
  daily quota. Cooldowns are capped at seven days and expire automatically.
- `401`, `402`, and `403` skip the provider with a five-minute default cooldown;
  `404` and `410` pause only that model. `500`, `502`, `503`, `504`, and pre-stream
  connection failures pause the provider with a 60-second default cooldown.
- OrcaRouter `429` without `Retry-After` indicates a prompt-size cap, not an
  exhausted quota window. It can fail over but does not cool the account.
- Input errors such as `400`, `413`, and `422` return to the caller without
  cycling providers. Fix the payload or select a suitable explicit provider.
- The pool attempts at most eight candidates and has a 120-second response
  deadline, with bounded connection/read timeouts. It never sleeps waiting for
  quota. A stalled read can last until its read timeout.
- Malformed/empty successful responses and initial SSE errors can fail over.
  Once streaming begins, the chosen provider is fixed. Interrupted/malformed
  streams emit `free_stream_interrupted`; another model is never appended to a
  partial answer. A valid refusal is an answer, not an availability failure.
- All candidates cooling down returns `429 free_pool_exhausted` plus the
  earliest `Retry-After`; no configured eligible models returns `503
  free_models_unavailable`. Attempt/deadline exhaustion returns `503
  free_attempt_limit`. No paid model is substituted.

These are reactive cooldowns, not quota reservations: simultaneous requests can
reach a provider before the first quota response is observed. Cooldowns share
the model-registry SQLite database across local workers. Cloud containers lose
local state on replacement unless the existing external PostgreSQL control
plane is configured. Upstream account quotas remain authoritative after a
restart. Do not rotate keys to evade an organization's quota.

[Groq's headers](https://console.groq.com/docs/rate-limits) distinguish daily
requests from per-minute tokens; the route does not assume that all header
counters are per minute. Gemini uses its
[OpenAI-compatible endpoint](https://ai.google.dev/gemini-api/docs/openai).

## Test after starting or deploying this revision

Text example, using a proxy key already stored securely in your environment:

```bash
curl -i http://localhost:1400/v1/chat/completions \
  -H "Authorization: Bearer $MULTILLM_PROXY_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"free:text","messages":[{"role":"user","content":"Reply with one short greeting."}],"max_tokens":80}'
```

For vision, use `/v1/chat/completions` and this body. The fixed
`/v1/free/vision/chat/completions` path remains supported. Replace the
image URL with a synthetic/public image, or an inline PNG/JPEG/WebP/GIF data URL:

```json
{
  "model": "free:vision",
  "messages": [{"role": "user", "content": [
    {"type": "text", "text": "Describe the visible objects in this image."},
    {"type": "image_url", "image_url": {"url": "https://example.com/test-image.png"}}
  ]}],
  "max_tokens": 200
}
```

The proxy preserves image content during fallback and does not fetch image URLs
itself. Each provider's size, image-count, context and data-retention rules still
apply. Use synthetic material when testing free tiers; do not send confidential
documents without checking the provider's terms.

Add `"stream": true` and `curl -N` for SSE. The default output budget is 1,024
tokens unless `max_tokens` or `max_completion_tokens` is provided. Messages must
contain nonempty text or supported content parts. Query parameters, custom
model/provider fallback lists, plugins, tools, audio/file inputs and other
unrecognized parameters are rejected; caller billing/routing headers are not
forwarded. Common sampling, reasoning-effort and response-format parameters are
passed through, and must be supported by the selected upstream model.

Inspect `/v1/free/models` for candidate IDs, configured status, vision support,
billing basis, and remaining cooldown seconds. It contains no keys. Response
headers `X-MultiLLM-Auto-Route`, `X-MultiLLM-Auto-Selected-Model`,
`X-MultiLLM-Auto-Attempts`, `X-MultiLLM-Auto-Selected-Priority`, and
`X-MultiLLM-Provider` identify what was selected. They are exposed through CORS.

Inspect `/v1/free/providers` for safe configuration status: key environment
names, enablement, required free-tier assertions and missing settings. It does
not validate live credentials or return secret/account values.

Regression tests simulate quota exhaustion; they do not deliberately consume
live daily quotas or send private prompts to providers:

```bash
python -m pytest -q tests/test_free_routes.py tests/test_free_quota_service.py
node --test tests/test_free_routes_worker.mjs
```
