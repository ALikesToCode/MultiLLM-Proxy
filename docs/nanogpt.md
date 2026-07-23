# NanoGPT gateway

MultiLLM Proxy exposes NanoGPT as a raw, protocol-preserving provider under
`/nanogpt/*`. Request bodies, multipart boundaries, binary responses, JSON
bytes, SSE event types, query parameters, status codes, and safe upstream
response headers are not translated.

The implementation follows NanoGPT's live
[full documentation](https://docs.nano-gpt.com/llms-full.txt) and
[OpenAPI document](https://docs.nano-gpt.com/api-reference/openapi.json).
Model and feature availability changes over time, so applications should use
the catalog endpoints instead of hard-coding model IDs.

## Configuration

```env
NANOGPT_API_KEY=your-nanogpt-api-key

# Optional overrides
NANOGPT_BASE_URL=https://nano-gpt.com/api
NANOGPT_BATCH_BASE_URL=https://api.nano-gpt.com/api/v1
NANOGPT_ORIGIN_URL=https://nano-gpt.com
NANOGPT_MAX_REQUEST_BYTES=16777216
```

The default request limit is 16 MiB. Increase it only when a documented media
endpoint requires a larger body and the deployment can safely accept it.

## URL mapping

Use the proxy origin in place of NanoGPT's origin:

| NanoGPT URL family | Proxy URL family |
| --- | --- |
| `https://nano-gpt.com/api/<path>` | `$PROXY_BASE_URL/nanogpt/<path>` |
| `https://api.nano-gpt.com/api/v1/files*` | `$PROXY_BASE_URL/nanogpt/v1/files*` |
| `https://api.nano-gpt.com/api/v1/batches*` | `$PROXY_BASE_URL/nanogpt/v1/batches*` |
| `https://nano-gpt.com/oauth/register` | `$PROXY_BASE_URL/nanogpt/oauth/register` |
| `https://nano-gpt.com/oauth/token` | `$PROXY_BASE_URL/nanogpt/oauth/token` |
| `https://nano-gpt.com/.well-known/*` | `$PROXY_BASE_URL/nanogpt/.well-known/*` |

The proxy automatically sends `/v1/files*` and `/v1/batches*` to NanoGPT's
dedicated batch host. Callers do not need a second proxy base URL.

Browser authentication remains direct:

- `https://nano-gpt.com/auth`
- `https://nano-gpt.com/oauth/authorize`
- `https://nano-gpt.com/cli-login/verify`

Those pages depend on browser redirects or session cookies, which the raw
credential-isolated transport deliberately does not proxy.

## Authentication

For the common server-key flow, authenticate to MultiLLM Proxy with either an
OpenAI-style bearer header or an Anthropic-style API-key header. The proxy
replaces it with `NANOGPT_API_KEY` upstream.

```bash
# OpenAI-style client
curl "$PROXY_BASE_URL/nanogpt/v1/chat/completions" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"MODEL_FROM_CATALOG","messages":[{"role":"user","content":"Hello"}]}'

# Anthropic-style client
curl "$PROXY_BASE_URL/nanogpt/v1/messages" \
  -H "X-Api-Key: $ADMIN_API_KEY" \
  -H "Anthropic-Version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"MODEL_FROM_CATALOG","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}'
```

When the upstream credential must come from the caller, put the proxy
credential in `X-MultiLLM-Api-Key`. This leaves the native authentication
header available for a NanoGPT OAuth key, partner JWT, downstream user key, or
other caller-scoped credential:

```bash
curl "$PROXY_BASE_URL/nanogpt/v1/chat/completions" \
  -H "X-MultiLLM-Api-Key: $ADMIN_API_KEY" \
  -H "Authorization: Bearer $USER_NANOGPT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"MODEL_FROM_CATALOG","messages":[{"role":"user","content":"Hello"}]}'
```

`X-MultiLLM-Api-Key` can also be combined with `X-Api-Key` when the caller
wants to supply NanoGPT's native API-key header. Caller-supplied authentication
works even when `NANOGPT_API_KEY` is not configured.

Public or optional-auth NanoGPT endpoints still require a valid MultiLLM Proxy
credential; “public” only means the proxy does not add a NanoGPT credential.

## Capability map

All documented methods under these paths are passed through. The table groups
the current public surface; consult the live docs for each request schema and
model-specific parameters.

| Capability | NanoGPT paths exposed under `/nanogpt` |
| --- | --- |
| OpenAI text | `/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/responses/{id}` |
| Alternate text modes | `/v1legacy/chat/completions`, `/v1thinking/chat/completions`, `/subscription/v1/chat/completions` |
| Anthropic Messages | `/v1/messages`, `/v1/messages/count_tokens` |
| Models and routing | `/v1/models`, `/paid/v1/models`, `/subscription/v1/models`, `/personalized/v1/models`, `/models/{model}/providers` |
| Usage and balance | `/v1/usage`, `/subscription/v1/usage`, `/check-balance` |
| Embeddings | `/v1/embeddings`, `/v1/embedding-models` |
| Moderation and detection | `/v1/moderations`, `/v1/moderation-models`, `/v1/ai-detection`, `/nsfw/image` |
| Images and edits | `/v1/images`, `/v1/images/generations`, `/v1/images/edits`, `/v1/images/edit` |
| Image discovery | `/v1/image-models`, `/v1/images/models`, `/v1/images/models/{model}/endpoints` |
| Video | `/generate-video`, `/video/status`, `/generate-video/content`, `/generate-video/recover`, `/v1/video-models` |
| Text to speech | `/v1/audio/speech`, `/v1/speech`, `/tts`, `/tts/status` |
| Speech to text and cloning | `/v1/audio/transcriptions`, `/transcribe`, `/transcribe/status`, `/voice-clone/minimax`, `/v1/audio-models` |
| Memory | `/v1/memory` |
| Search and extraction | `/v1/data/web/search`, `/v1/data/url/scrape`, `/v1/data/x/search`, `/v1/data/google-maps/search`, `/v1/data/hunter/domain-search` |
| Provider-native data APIs | `/v1/firecrawl`, `/v1/googlemaps`, `/v1/hunter`, `/v1/reddit`, `/v1/facebook/ads`, `/v1/instagram/*`, `/v1/tiktok` |
| Convenience extraction | `/scrape-urls`, `/youtube-transcribe`, `/web` |
| Batch files and jobs | `/v1/files*`, `/v1/batches*` |
| Characters | `/v1/characters`, `/v1/character-models` |
| Evals | `/v1/evals/datasets*`, `/v1/evals/experiments*`, `/v1/evals/scorers*` |
| TEE verification | `/v1/tee/attestation`, `/v1/tee/signature/{requestId}` |
| Accountless payments | `/v1/x402/endpoints`, `/x402/complete/{id}`, `/x402/status/{id}` |
| Deposits and invitations | `/transaction/*`, `/invitations/create` |
| Partner and key management | `/partners/*`, `/user/provider-keys`, `/v1/auth/keys`, `/v1/auth/keys/code` |
| OAuth PKCE machine endpoints | `/.well-known/*`, `/oauth/register`, `/oauth/token`, `/auth.md` |

### OpenAI Responses

NanoGPT is treated as a native Responses provider. Both direct and unified
routes preserve its native response:

```bash
curl "$PROXY_BASE_URL/v1/responses" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"nanogpt:MODEL_FROM_CATALOG","input":"Summarize this change","stream":true}'
```

The unified route only changes the `nanogpt:` model prefix. It does not bridge
the request through Chat Completions.

### Media and multipart bodies

```bash
curl "$PROXY_BASE_URL/nanogpt/v1/audio/transcriptions" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -F "file=@audio.mp3" \
  -F "model=MODEL_FROM_AUDIO_CATALOG"
```

Binary audio and image responses are streamed unchanged. Video and asynchronous
audio calls return their native job IDs; poll the corresponding NanoGPT status
path through the same `/nanogpt` prefix.

### Batches

```bash
curl "$PROXY_BASE_URL/nanogpt/v1/files" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -F "purpose=batch" \
  -F "file=@requests.jsonl"

curl "$PROXY_BASE_URL/nanogpt/v1/batches" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"input_file_id":"file_...","endpoint":"/v1/chat/completions","completion_window":"24h"}'
```

### Accountless x402 and L402

For an initial quote, authenticate the proxy normally and request an
accountless quote. The configured NanoGPT key is deliberately omitted:

```bash
curl "$PROXY_BASE_URL/nanogpt/v1/chat/completions" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "x-x402: true" \
  -H "Content-Type: application/json" \
  -d '{"model":"MODEL","messages":[{"role":"user","content":"Hello"}]}'
```

For a payment replay, forward NanoGPT's `X-PAYMENT` header. For L402, separate
the two credentials:

```bash
curl "$PROXY_BASE_URL/nanogpt/v1/chat/completions" \
  -H "X-MultiLLM-Api-Key: $ADMIN_API_KEY" \
  -H "Authorization: L402 $L402_CREDENTIAL" \
  -H "Content-Type: application/json" \
  -d @request.json
```

The proxy exposes `WWW-Authenticate`, `X-PAYMENT-RESPONSE`, and `X-Poll-After`
to browser clients.

## Transport and retry behavior

NanoGPT calls are single-attempt. The proxy does not follow upstream redirects,
store upstream cookies, normalize JSON/SSE, or automatically retry a paid
generation request. This avoids duplicated work and billing. Implement retries
in the caller only when the selected NanoGPT endpoint documents a safe
idempotency strategy.

## Intentional browser-session exclusions

NanoGPT web-app settings, Teams administration, conversation UI routes, and
other endpoints that require a `nano-gpt.com` browser session cookie are not
proxied. Forwarding those cookies through a shared server gateway would break
credential isolation. API-key, OAuth-key, partner-JWT, batch, billing, media,
data, and model endpoints listed above remain available. Use NanoGPT directly
for session-bound web UI and team-management operations.
