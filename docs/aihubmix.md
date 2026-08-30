# AIHubMix free models and image generation

MultiLLM-Proxy exposes AIHubMix through OpenAI-compatible unified routes and a
restricted native gateway. The built-in catalog contains every `-free` model
returned by AIHubMix on August 28, 2026, plus the requested Doubao Seedream
image model. A successful live catalog refresh supplements that snapshot.

Official references:

- [Documentation index](https://docs.aihubmix.com/llms.txt)
- [Free-model search](https://aihubmix.com/models?q=free)
- [`gpt-image-2-free`](https://aihubmix.com/model/gpt-image-2-free/llms.txt)
- [`gemini-3.1-flash-image-preview-free`](https://aihubmix.com/model/gemini-3.1-flash-image-preview-free/llms.txt)
- [`doubao-seedream-4-0`](https://aihubmix.com/model/doubao-seedream-4-0/llms.txt)

## Configuration

Keep the credential in the environment or a Cloudflare Worker secret:

```env
AIHUBMIX_API_KEY=your-aihubmix-api-key
AIHUBMIX_BASE_URL=https://aihubmix.com
AIHUBMIX_BACKUP_BASE_URL=https://api.inferera.com
```

Only those two HTTPS hosts are accepted. A configured origin may include a
trailing `/v1`; MultiLLM canonicalizes it to the origin before appending the
selected endpoint. Arbitrary hosts, credentials in URLs, ports, query strings,
and other paths are rejected in favor of the corresponding trusted default.

Direct `/aihubmix/*` calls authenticate to MultiLLM with `ADMIN_API_KEY`.
MultiLLM removes that caller credential and authenticates upstream with
`AIHUBMIX_API_KEY`.

```bash
export PROXY_BASE_URL="https://your-worker.example"
export ADMIN_API_KEY="your-proxy-key"
```

## Discover models

The native catalog shows the provider's current response:

```bash
curl "$PROXY_BASE_URL/aihubmix/v1/models" \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

The unified catalog combines the built-in snapshot, the last successful live
refresh, and saved route references. Its IDs include the provider prefix:

```bash
curl "$PROXY_BASE_URL/v1/models" \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

In the dashboard, open **Operations**, select **Refresh live models**, then
filter the model catalog by `aihubmix`. The `/docs` page reports whether the
credential is configured and lists the same built-in and refreshed models.

## Generate with GPT Image

The unified endpoint sends the documented OpenAI Images payload unchanged
after removing the `aihubmix:` prefix:

```bash
curl "$PROXY_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Idempotency-Key: image-123" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "aihubmix:gpt-image-2-free",
    "prompt": "A simple green triangle centered on a white background",
    "n": 1,
    "size": "1024x1024",
    "quality": "low",
    "moderation": "low",
    "output_format": "png"
  }'
```

The response remains OpenAI-compatible, including `data[].b64_json` and any
provider-supplied `usage` object. Provider-side free-channel availability can
change; a structured `no_available_channel` response is passed through rather
than hidden or retried as another model.

`moderation` accepts `low` or `auto`. MultiLLM inserts `low` when it is omitted.
The setting applies to GPT Image generation only, not the multipart edit route.

Image editing uses the native multipart route so file bytes remain unchanged:

```bash
curl "$PROXY_BASE_URL/aihubmix/v1/images/edits" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Idempotency-Key: image-edit-123" \
  -F "model=gpt-image-2-free" \
  -F "image=@input.png;type=image/png" \
  -F "prompt=Change the red circle to a blue square" \
  -F "n=1" \
  -F "size=1024x1024" \
  -F "quality=low" \
  -F "output_format=png"
```

## Generate with Gemini Flash Image

The unified image route converts an OpenAI Images-shaped request into
AIHubMix's multimodal Chat Completions contract and converts returned inline
image parts or URLs back into OpenAI `data[]` entries:

```bash
curl "$PROXY_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "aihubmix:gemini-3.1-flash-image-preview-free",
    "prompt": "A paper fox on a wooden desk",
    "n": 1,
    "temperature": 0.4
  }'
```

This translation currently supports one image per request. Use the native
`/aihubmix/v1/chat/completions` route when the caller needs AIHubMix's exact
multimodal response rather than the normalized OpenAI Images response.

## Generate with Doubao Seedream

The same unified endpoint maps the prompt into the documented prediction
contract and normalizes returned URLs or Base64 data:

```bash
curl "$PROXY_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "aihubmix:doubao-seedream-4-0",
    "prompt": "A glass observatory above a cloud sea",
    "size": "2K",
    "watermark": false,
    "n": 1
  }'
```

For the native response shape, call:

```text
POST /aihubmix/v1/models/doubao/doubao-seedream-4-0/predictions
```

## Trusted-origin failover

The primary origin is always tried first. MultiLLM uses the backup only after
a definite proxy transport failure, never after a real HTTP error returned by
AIHubMix. `GET`, `HEAD`, and `OPTIONS` are replayed automatically. A mutation is
replayed only when the caller explicitly supplies a non-empty
`Idempotency-Key`; without it, the first transport result is returned to avoid
an automatic duplicate generation. Provider-side interpretation of that key
still governs true deduplication, so callers should use a unique key and keep
their own result record.

## Built-in free-model snapshot

These 54 free IDs are available immediately at startup. Refresh the provider
catalog before choosing a production model because availability and limits can
change.

```text
coding-glm-4.6-free
coding-glm-4.7-free
coding-glm-5-free
coding-glm-5-turbo-free
coding-glm-5.1-free
coding-glm-5.2-free
coding-glm-5.3-free
coding-kimi-k3-free
coding-minimax-m2-free
coding-minimax-m2.1-free
coding-minimax-m2.5-free
coding-minimax-m2.7-free
coding-minimax-m3-free
dots-3-note-preview-free
gemini-3-flash-preview-free
gemini-3.1-flash-image-preview-free
gemini-3.5-flash-lite-free
gemini-3.6-flash-free
gemini-3.7-flash-free
gemma-4-26b-a4b-it-free
gemma-4-31b-it-free
glm-4.7-flash-free
gpt-4.1-free
gpt-4.1-mini-free
gpt-4.1-nano-free
gpt-4o-free
gpt-5.5-free
gpt-image-2-free
gpt-oss-20b-free
hy3-free
k2.6-code-preview-free
kimi-for-coding-free
laguna-s-2.1-free
laguna-xs-2.1-free
lfm-2.5-2.6b-free
ling-3.0-flash-free
ling-3.0-tiny-free
mimo-v2-flash-free
minimax-m2.7-free
minimax-m3-free
nemotron-3-nano-30b-a3b-free
nemotron-3-nano-omni-30b-a3b-reasoning-free
nemotron-3-super-120b-a12b-free
nemotron-3-ultra-550b-a55b-free
nemotron-3.5-content-safety-free
nemotron-3.5-lightning-free
nemotron-nano-12b-v2-vl-free
nemotron-nano-9b-v2-free
north-mini-code-free
qwen3.6-plus-preview-free
xiaomi-mimo-v2-omni-free
xiaomi-mimo-v2-pro-free
xiaomi-mimo-v2.5-free
xiaomi-mimo-v2.5-pro-free
```

`doubao-seedream-4-0` is included as an additional requested image model even
though its ID does not end in `-free`.

## Native route boundary

The native gateway accepts only these documented method/path pairs:

| Method | Route |
| --- | --- |
| `GET` | `/aihubmix/v1/models` |
| `POST` | `/aihubmix/v1/chat/completions` |
| `POST` | `/aihubmix/v1/images/generations` |
| `POST` | `/aihubmix/v1/images/edits` |
| `POST` | `/aihubmix/v1/models/doubao/doubao-seedream-4-0/predictions` |

Unknown paths, traversal segments, encoded delimiters, and wrong methods are
rejected before any upstream request.
