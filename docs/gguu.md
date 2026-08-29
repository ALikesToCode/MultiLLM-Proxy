# GGUU AI image generation

MultiLLM exposes GGUU AI as a credential-isolated OpenAI Images provider. The
normalized model ID is `gguu:gpt-image-2`; native requests use the `/gguu/*`
namespace. Chat and Responses routes are not advertised because GGUU's current
GPT Image 2 guide documents the Images API only.

## Configuration

Set the provider credential without committing it:

```dotenv
GGUU_API_KEY=your-gguu-api-key
```

The built-in primary origin is `https://gguuai.com`. The bounded backup origin
is `https://api.aiaimax.com`. A safe `GET /v1/models` transport failure can use
the backup automatically. A paid `POST` is replayed only after a definite
transport failure and only when the client supplied an `Idempotency-Key`.
Upstream HTTP errors are returned without cross-origin retry.

GGUU's public guide does not state whether idempotency keys are deduplicated
across both hostnames. Omit `Idempotency-Key` to disable paid-request replay, or
confirm GGUU's current behavior before relying on automatic POST failover.

For Cloudflare, store the credential as a Worker secret. Adding a secret creates
and deploys a Worker version:

```bash
npx wrangler secret put GGUU_API_KEY
```

## Unified image generation

```bash
curl "$PROXY_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gguu:gpt-image-2",
    "prompt": "An orange cat wearing sunglasses, cyberpunk style",
    "size": "3840x2160",
    "quality": "high",
    "output_format": "png",
    "response_format": "url",
    "n": 1
  }'
```

The unified endpoint removes the `gguu:` prefix and preserves the remaining
OpenAI Images request and response fields.

## Native endpoints

| Method | MultiLLM path | Purpose |
| --- | --- | --- |
| `GET` | `/gguu/v1/models` | Live provider catalog |
| `POST` | `/gguu/v1/images/generations` | Text-to-image generation |
| `POST` | `/gguu/v1/images/edits` | Multipart image editing |

Native text-to-image example:

```bash
curl "$PROXY_BASE_URL/gguu/v1/images/generations" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-image-2",
    "prompt": "A glass observatory at sunrise",
    "size": "2048x2048",
    "quality": "high",
    "output_format": "png",
    "response_format": "b64_json",
    "n": 1
  }'
```

Native multipart edit example:

```bash
curl "$PROXY_BASE_URL/gguu/v1/images/edits" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -F "model=gpt-image-2" \
  -F "prompt=Remove the sunglasses and add a hat" \
  -F "image=@input.jpg" \
  -F "size=1024x1024" \
  -F "quality=high" \
  -F "input_fidelity=high" \
  -F "output_format=png" \
  -F "response_format=url"
```

The proxy preserves the multipart boundary and binary body without JSON
normalization.

## Current provider constraints

- `model` is `gpt-image-2`.
- `n` must be `1`.
- `size` may be `auto` or a valid size up to `3840x2160`; dimensions must be
  multiples of 16, total pixels must be between 655,360 and 8,294,400, and the
  longest-to-shortest-side ratio must not exceed 3:1.
- `quality` accepts `low`, `medium`, `high`, or `auto`.
- `response_format` accepts `url` or `b64_json`.
- `output_format` should be `png` or `jpeg`.
- Image edits accept one image, an optional PNG mask, and optional
  `input_fidelity=high`.
- Streaming and partial-image events are not supported by this route.

Use the live `/gguu/v1/models` response and the provider dashboard as the
source of truth if these limits change.
