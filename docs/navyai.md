# NavyAI gateway

MultiLLM Proxy exposes NavyAI under `/navyai/*` as a raw gateway. OpenAI SSE,
Anthropic SSE, multipart uploads, binary audio, job payloads, JSON bytes, status
codes, and safe upstream response headers pass through without protocol
translation.

This integration follows the live [NavyAI documentation](https://api.navy/docs).
Use `GET /navyai/v1/models` to discover current models, plan gates,
capabilities, and token multipliers instead of hard-coding the catalog.

## Configuration

```env
NAVYAI_API_KEY=sk-navy-YOUR_KEY

# Optional
NAVYAI_BASE_URL=https://api.navy
NAVYAI_MAX_REQUEST_BYTES=33554432
```

The proxy default is 32 MiB so NavyAI's documented 25 MiB transcription upload
limit can pass through with multipart overhead.

## Client base URLs

| Client protocol | Proxy base URL |
| --- | --- |
| OpenAI-compatible clients | `$PROXY_BASE_URL/navyai/v1` |
| Anthropic-compatible clients | `$PROXY_BASE_URL/navyai` |
| Direct HTTP | `$PROXY_BASE_URL/navyai` plus the documented `/v1/...` path |

Examples:

```python
from openai import OpenAI

client = OpenAI(
    api_key="YOUR_MULTILLM_PROXY_KEY",
    base_url="https://your-proxy.example/navyai/v1",
)
```

```python
import anthropic

client = anthropic.Anthropic(
    api_key="YOUR_MULTILLM_PROXY_KEY",
    base_url="https://your-proxy.example/navyai",
)
```

The OpenAI client sends the proxy key as a bearer token; the Anthropic client
sends it as `x-api-key`. MultiLLM Proxy replaces either credential with
`NAVYAI_API_KEY` upstream.

## Coding agents and roleplay clients

NavyAI's documented client integrations use the same two protocol surfaces, so
they do not require separate proxy endpoints:

| Client family | MultiLLM Proxy base URL |
| --- | --- |
| Codex CLI and OpenAI-compatible coding agents | `$PROXY_BASE_URL/navyai/v1` |
| Claude Code and Anthropic-compatible coding agents | `$PROXY_BASE_URL/navyai` |
| Roo Code | Select its OpenAI or Anthropic mode and use the matching URL above |
| SillyTavern, Janitor AI, RisuAI, and Agnai | `$PROXY_BASE_URL/navyai/v1` with Chat Completions |

Use a MultiLLM Proxy API key in the client's API-key field and select a model
returned by `GET /navyai/v1/models`. The roleplay-client pages are configuration
guides over Chat Completions; they do not add undocumented NavyAI endpoints.

## Capability map

| Capability | Method and proxy path |
| --- | --- |
| OpenAI Chat Completions | `POST /navyai/v1/chat/completions` |
| Anthropic Messages | `POST /navyai/v1/messages` |
| OpenAI Responses | `POST /navyai/v1/responses` |
| Image generation and editing | `POST /navyai/v1/images/generations` |
| Image/video job polling | `GET /navyai/v1/images/generations/{id}` |
| Text to speech | `POST /navyai/v1/audio/speech` |
| Synchronous transcription | `POST /navyai/v1/audio/transcriptions` |
| Asynchronous transcription | `POST /navyai/v1/audio/transcriptions/jobs` |
| Transcription job status | `GET /navyai/v1/audio/transcriptions/jobs/{id}/status` |
| Subtitle/transcript download | `GET /navyai/v1/audio/transcriptions/jobs/{id}/download` |
| Embeddings | `POST /navyai/v1/embeddings` |
| Moderation | `POST /navyai/v1/moderations` |
| Model catalog | `GET /navyai/v1/models` |
| Provider/model health | `GET /navyai/v1/models/status` |
| Plan and rate usage | `GET /navyai/v1/usage` |
| OAuth token exchange/refresh | `POST /navyai/v1/oauth/token` |
| OAuth user profile | `GET /navyai/v1/oauth/me` |
| OAuth grant revocation | `POST /navyai/v1/oauth/revoke` |

Chat supports streaming, vision parts, tool/function calls, structured output,
sampling controls, and `reasoning_effort`. Messages preserves Anthropic-native
content blocks, tools, vision, and event types. Responses preserves typed
streaming events, function tools, reasoning controls, schema-driven text, and
supported provider-native built-in tools.

The image endpoint also accepts reference image URLs for editing. Image calls
can be synchronous or use `"sync": false`; video models always use jobs. Poll
until the native job status is `completed` or `failed`. NavyAI currently keeps
completed image/video jobs for ten minutes.

Text-to-speech responses are normally binary audio. Some ElevenLabs timestamp
modes return JSON. Synchronous and asynchronous speech-to-text uploads are
multipart requests. Completed asynchronous transcript/subtitle downloads are
currently retained for one hour.

## Direct routes and unified text routes

Direct Chat:

```bash
curl "$PROXY_BASE_URL/navyai/v1/chat/completions" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"MODEL_FROM_CATALOG","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

Native Anthropic Messages:

```bash
curl "$PROXY_BASE_URL/navyai/v1/messages" \
  -H "X-Api-Key: $ADMIN_API_KEY" \
  -H "Anthropic-Version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"MODEL_FROM_CATALOG","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

NavyAI is a native Responses provider on the unified route:

```bash
curl "$PROXY_BASE_URL/v1/responses" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"navyai:MODEL_FROM_CATALOG","input":"Draft a release note","stream":true}'
```

The unified Chat and Responses routes remove only the `navyai:` model prefix.
They do not convert NavyAI's native response format.

## Images, video jobs, and audio

```bash
JOB_ID="$(
  curl -sS "$PROXY_BASE_URL/navyai/v1/images/generations" \
    -H "Authorization: Bearer $ADMIN_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"model":"VIDEO_MODEL","prompt":"A ship entering harbor at sunrise","sync":false}' |
  jq -r '.id'
)"

curl "$PROXY_BASE_URL/navyai/v1/images/generations/$JOB_ID" \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

```bash
curl "$PROXY_BASE_URL/navyai/v1/audio/transcriptions" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -F "file=@audio.mp3" \
  -F "model=TRANSCRIPTION_MODEL"
```

The proxy preserves the multipart boundary and file bytes. It also streams
binary bodies from `/v1/audio/speech` and completed job downloads unchanged.

## Login with Navy OAuth

Start the browser authorization flow directly at:

```text
https://api.navy/v1/oauth/authorize
```

The authorize step depends on a browser redirect and NavyAI session, so
`GET /navyai/v1/oauth/authorize` intentionally returns a helpful `400` instead
of attempting an incomplete proxied login.

Token exchange, refresh, profile lookup, inference with user tokens, and
revocation can use the proxy. Separate the MultiLLM credential from the
upstream OAuth credential:

```bash
curl "$PROXY_BASE_URL/navyai/v1/oauth/me" \
  -H "X-MultiLLM-Api-Key: $ADMIN_API_KEY" \
  -H "Authorization: Bearer $NAVY_OAUTH_ACCESS_TOKEN"
```

The same header pair works for inference billed to the OAuth user's plan.
Caller-supplied OAuth authentication works without `NAVYAI_API_KEY`.

The token endpoint itself is public upstream, but remains protected by
MultiLLM Proxy authentication:

```bash
curl "$PROXY_BASE_URL/navyai/v1/oauth/token" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type":"authorization_code",
    "code":"ONE_TIME_CODE",
    "redirect_uri":"https://yourapp.example/auth/navy/callback",
    "client_id":"navy-client-...",
    "client_secret":"navy-secret-...",
    "code_verifier":"THE_ORIGINAL_VERIFIER"
  }'
```

If NavyAI client authentication uses HTTP Basic, authenticate MultiLLM Proxy
with `X-MultiLLM-Api-Key` and put the Basic credential in `Authorization`.
OAuth codes, verifiers, client secrets, access tokens, and refresh tokens are
redacted from proxy logs.

## Transport, errors, and retries

NavyAI uses OpenAI-style JSON errors for non-streaming calls and sends errors as
SSE data events after a stream has begun. The proxy preserves both forms.

Raw NavyAI calls are single-attempt. NavyAI already retries upstream providers,
and an extra transparent proxy retry could duplicate a paid image, video,
speech, or text generation. Callers may retry `429`, `500`, `502`, and `503`
with backoff when appropriate, but should not retry `400`, `401`, `403`, or
`404` without correcting the request. Use `/navyai/v1/usage` to read quota and
reset state after `429`.

The transport does not follow upstream redirects or retain upstream cookies.
This protects credentials and is why the browser authorization step stays
direct.

## Documentation coverage

This integration covers the public API described by NavyAI's
[overview](https://api.navy/docs),
[authentication](https://api.navy/docs/authentication),
[agent configuration](https://api.navy/docs/agents),
[endpoint index](https://api.navy/docs/api-endpoints),
[Chat Completions](https://api.navy/docs/chat-completions),
[Anthropic Messages](https://api.navy/docs/messages-anthropic),
[Responses](https://api.navy/docs/responses),
[embeddings](https://api.navy/docs/embeddings),
[image generation](https://api.navy/docs/image-generation),
[job polling](https://api.navy/docs/job-polling),
[text-to-speech](https://api.navy/docs/text-to-speech),
[speech-to-text](https://api.navy/docs/speech-to-text),
[asynchronous transcription](https://api.navy/docs/async-speech-to-text-jobs),
[moderation](https://api.navy/docs/moderations),
[models and health](https://api.navy/docs/models),
[usage](https://api.navy/docs/usage-statistics),
[errors and rate limits](https://api.navy/docs/errors), and
[OAuth PKCE](https://api.navy/docs/oauth).

NavyAI also publishes configuration pages for
[SillyTavern](https://api.navy/docs/sillytavern),
[Janitor AI](https://api.navy/docs/janitor-ai),
[RisuAI](https://api.navy/docs/risuai), and
[Agnai](https://api.navy/docs/agnai). Its legal documents remain upstream:
[privacy](https://api.navy/privacy),
[terms](https://api.navy/terms), and
[legal notice](https://api.navy/legal-notice).
