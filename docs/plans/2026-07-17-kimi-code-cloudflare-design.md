# Kimi Code Cloudflare Provider Design

## Goal

Add Kimi Code as the `kimi-code` provider with the official OpenAI-compatible
base URL `https://api.kimi.com/coding/v1` and the `k3` model. The production
route should be fast and cost-conscious on Cloudflare while preserving Kimi's
native Chat Completions behavior.

The public proxy base URL will be:

```text
$PROXY_BASE_URL/kimi-code/v1
```

The initial provider surface is deliberately limited to the two verified
paths:

- `GET /kimi-code/v1/models`
- `POST /kimi-code/v1/chat/completions`

Kimi Code does not currently document an OpenAI Responses endpoint, so the
provider will not forward `/v1/responses`. K3 examples use
`reasoning_effort: "max"`; the proxy preserves caller fields and never injects
or overrides reasoning settings.

## Approaches Considered

1. Container-only OpenAI compatibility would require the Flask Container for
   every call. It is the smallest code change but adds cold-start latency and
   Container runtime cost.
2. A direct Kimi Worker fast path plus a strict Flask fallback keeps normal
   Kimi traffic on the edge, streams bytes unchanged, and matches the existing
   LinkAPI and Codex Everywhere architecture. This is the selected approach.
3. Replacing all direct providers with a new generic provider framework would
   reduce some duplication, but it would expand the release into a risky
   cross-provider refactor without improving Kimi request latency.

## Architecture and Data Flow

The Cloudflare Worker recognizes the `/kimi-code` namespace before it considers
waking the Container. It validates the path, authenticates the caller against
the bootstrap `ADMIN_API_KEY` with a timing-safe comparison, removes proxy
credentials, and authenticates upstream with the `KIMI_CODE_API_KEY` secret.
The upstream host and `/coding/v1` prefix are fixed in code and cannot be
selected by a caller.

Request and response bodies pass through as streams. This preserves OpenAI SSE
frames, Kimi `reasoning_content`, tool calls, multimodal inputs, and a caller's
`prompt_cache_key`. The Worker forwards a truthful caller `User-Agent` and
recognized OpenAI SDK metadata headers, uses the incoming abort signal, follows
no redirects, performs one upstream fetch, and never uses the Cache API for
generation traffic.

The Flask route provides the same exact-path behavior for non-Cloudflare
deployments and controlled unified Chat Completions. Kimi joins the raw Chat
passthrough set so Flask does not normalize SSE, filter reasoning fields,
retry a billed generation, share upstream cookies, or translate tool output.
Unified `/v1/responses` requests using a `kimi-code:*` model are rejected with
a clear client error because Kimi Code does not document that protocol.

## Registration and Controls

Provider registration uses the `kimi-code` slug, the fixed official base URL,
a long-running agent timeout, and the exact model ID `k3`. The provider key is
loaded only from `KIMI_CODE_API_KEY`. The Worker forwards that secret into the
Container and supports the existing `KIMI_CODE_*` per-provider limit variables.

Direct Worker calls intentionally use only `ADMIN_API_KEY` and therefore bypass
Flask users, application request-size controls, rate limits, request accounting,
and metrics. Clients that require those controls use the Container-backed
unified `/v1/chat/completions` route with model `kimi-code:k3`.

The proxy does not retry Kimi generation calls. Upstream authentication,
entitlement, quota, overload, and transport errors are returned safely so the
caller can decide whether a retry is appropriate. Error logs contain event and
error-class metadata, not URLs, tokens, request bodies, or upstream messages.

## Verification and Release

Tests are written before implementation and cover registration, exact URL
joining without a duplicate `/v1`, key loading, raw Flask transport, safe
headers, query-key removal, byte-for-byte SSE, strict encoded-path rejection,
single-attempt behavior, cookie isolation, Worker authentication, direct
streaming, abort propagation, manual redirects, CORS, Container bypass, and
secret/config hygiene.

Release verification includes the focused tests, full Python and Worker suites,
Ruff, MyPy, syntax checks, static-secret scanning, Wrangler type generation,
and a Wrangler dry run. The `.env` value is uploaded as the Cloudflare secret
`KIMI_CODE_API_KEY` without printing it. Production proof requires healthy
`/health` and `/ready`, a `401` without proxy authentication, an authenticated
model list containing `k3`, and exactly one minimal `k3` Chat Completions call
using `reasoning_effort: "max"` with automatic retries disabled.

## Sources

- [Kimi Code overview](https://www.kimi.com/code/docs/en/)
- [Kimi Code model configuration](https://www.kimi.com/code/docs/en/kimi-code/models.html)
- [Kimi Code error reference](https://www.kimi.com/code/docs/en/kimi-code/error-reference.html)
- [Kimi Chat Completions reference](https://platform.kimi.ai/docs/api/chat)
- [Cloudflare Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)
