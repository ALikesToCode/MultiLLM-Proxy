# LinkAPI chat and image generation

MultiLLM-Proxy preserves LinkAPI's native OpenAI, Anthropic, and Gemini
protocols. The proxy does not translate image payloads or responses, so use the
endpoint listed for the selected model in LinkAPI's live catalog.

Official references:

- [LinkAPI documentation](https://docs.linkapi.ai/)
- [Live model catalog and pricing](https://linkapi.ai/pricing)

## Configuration

Set the upstream LinkAPI credential as `LINKAPI_KEY`. `LINKAPI_API_KEY` remains
an alias, but `LINKAPI_KEY` is preferred.

Direct `/linkapi/*` requests use `ADMIN_API_KEY` as the caller credential. The
Worker removes it and authenticates upstream with `LINKAPI_KEY`.

```bash
export PROXY_BASE_URL="https://your-worker.example"
export ADMIN_API_KEY="your-proxy-key"
```

## Discover current models

LinkAPI's catalog is dynamic, so query it instead of hard-coding model IDs:

```bash
curl "$PROXY_BASE_URL/linkapi/v1/models" \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

The direct route returns LinkAPI's response unchanged.

## Generate with GPT Image

`gpt-image-2-c` exposes LinkAPI's OpenAI Images generation and edit contracts.

Use the unified route when you need the proxy's normal request-size checks,
rate limits, accounting, and metrics:

```bash
curl -X POST "$PROXY_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "linkapi:gpt-image-2-c",
    "prompt": "A navy command room at dusk, cinematic lighting",
    "size": "1024x1024",
    "quality": "standard",
    "style": "vivid",
    "n": 1,
    "response_format": "url"
  }'
```

Use the raw Worker route for the lowest proxy overhead:

```bash
curl -X POST "$PROXY_BASE_URL/linkapi/v1/images/generations" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-image-2-c",
    "prompt": "A navy command room at dusk, cinematic lighting",
    "size": "1024x1024",
    "quality": "standard",
    "style": "vivid",
    "n": 1,
    "response_format": "url"
  }'
```

LinkAPI's live model detail shows `response_format` with `url` as the default.
The proxy preserves the selected upstream-supported format and all safe response
metadata.

Image editing is available on the direct multipart route:

```bash
curl -X POST "$PROXY_BASE_URL/linkapi/v1/images/edits" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -F "model=gpt-image-2-c" \
  -F "prompt=Add soft cinematic lighting" \
  -F "image=@input.png"
```

The unified route currently handles JSON image generation only. Use the direct
route for multipart edits.

## Generate with Gemini Flash Image

Gemini image models expose LinkAPI's native Gemini `generateContent` contract.
Native Gemini is preferred because it preserves image parts exactly:

```bash
curl -X POST \
  "$PROXY_BASE_URL/linkapi/v1beta/models/gemini-2.5-flash-image:generateContent" \
  -H "x-goog-api-key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [{
      "parts": [{
        "text": "Create a watercolor lighthouse at dawn"
      }]
    }],
    "generationConfig": {
      "responseModalities": ["TEXT", "IMAGE"]
    }
  }'
```

The response remains Gemini-native. Read image data from the returned content
parts; MultiLLM-Proxy does not convert those parts into OpenAI `data[]` objects.

## Current image-model snapshot

This snapshot was verified against LinkAPI Standard pricing on July 23, 2026.
The live catalog, prices, group ratios, and per-model limits can change.

| Model | Pricing shown |
| --- | --- |
| `gemini-2.5-flash-image` | ¥0.08/request |
| `gemini-3-pro-image` | ¥3.20 input and ¥192 output per 1M tokens |
| `gemini-3-pro-image-preview` | ¥0.35/request |
| `gemini-3.1-flash-image` | ¥0.80 input and ¥96 output per 1M tokens |
| `gemini-3.1-flash-image-preview` | ¥0.15/request |
| `gemini-3.1-flash-lite-image` | ¥0.08/request |
| `gpt-image-2` | ¥28 input, ¥105 output, and ¥7 cached input per 1M tokens |
| `gpt-image-2-c` | ¥0.10/request |

For low-cost volume, start by testing `gemini-2.5-flash-image` or
`gemini-3.1-flash-lite-image`. Use `gpt-image-2` when its output quality or
OpenAI Images contract is more important than the lowest unit price. Confirm
quality, daily limits, and the endpoint shown in each model's live detail page
before committing production traffic.

## Operational behavior

- `/linkapi/*` is a raw Worker fast path on Cloudflare and does not wake the
  Flask Container.
- The raw path intentionally bypasses Flask dashboard-user authentication,
  application request-size checks, RPM/TPM/daily accounting, and metrics.
- `/v1/images/generations` uses the controlled Flask path and requires a
  `provider:model` ID such as `linkapi:gpt-image-2-c`.
- Generation requests are single-attempt. The proxy does not retry paid image
  calls or promise idempotency.
- Do not assume a subscription can sustain 10,000 image requests per day. Check
  the selected model's current RPM and RPD limits in LinkAPI before load
  testing.
