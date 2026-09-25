---
name: multillm-media
description: Generate images, image batches and videos through MultiLLM-Proxy's media gateway, which picks the best current model and falls back to another provider when one fails. Use when a task needs a generated picture, several pictures or a video clip.
---

# MultiLLM Media

Generate images and videos through the MultiLLM-Proxy gateway with one API key. The
gateway chooses the provider, falls back automatically, and keeps provider keys private.

Send `Authorization: Bearer $MULTILLM_API_KEY` from the user's private environment. Never
ask for the key in chat, print it, or save it in a repository. A key needs the `chat`
scope; the provider probe needs `admin`.

## Choose a route

| Model | Use it for | Order tried |
| --- | --- | --- |
| `auto:image` | Best quality (the default) | GPT Image 2.5 Sunburst, Flare and GPT Image 2 via GGUU, Grok Imagine Image 2.0 via GGUU, GPT Image 2.5 Sunburst via Cloudflare AI, OpenAI, Grok Imagine via xAI, GPT Image 2 via Together, AIHubMix's free GPT Image 2, Leonardo Lucid Origin on Workers AI |
| `auto:image-fast` | Drafts and iteration | GPT Image 2.5 Flare first |
| `auto:gpt-image-2.5` | Only the GPT Image 2.5 family | GGUU, then Cloudflare AI, then OpenAI |
| `auto:video` | Video clips | Veo 3.1 (Gemini API), Grok Imagine Video 1.5, Veo 3.1 on Cloudflare AI, Sora 2 Pro, Sora 2 |

Use `provider:model` (for example `gguu:gpt-image-2.5-flare`) only when the user names a
provider. Operators can reorder routes in Operations.

## Generate an image

```bash
curl -sS "$MULTILLM_BASE_URL/v1/images/generations" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" -H "Content-Type: application/json" \
  -d '{"model": "auto:image", "prompt": "A glass observatory at sunrise, photorealistic",
       "size": "3840x2160", "response_format": "url"}'
```

- `quality` defaults to `max` on automatic routes. Each fallback model receives the
  highest quality it supports (GPT Image 2 uses `high`), a size within its limits and
  only the fields it accepts, so send one request, not one per provider.
- `size` is `auto` or `WIDTHxHEIGHT`: edges at most 3840 and multiples of 16, ratio at
  most 3:1. Common sizes: `1024x1024`, `1536x1024`, `1024x1536`, `2048x2048`,
  `3840x2160`, `2160x3840`. Outputs above 2560x1440 are experimental.
- `n` from 1 to 10 generates that many images; each is a separate request that may use
  a different provider. Optional: `background` (`transparent` with PNG or WebP),
  `output_format` (`png`, `jpeg`, `webp`), `moderation` (defaults to `low`).
- The reply is OpenAI Images JSON: `data[].url` or `data[].b64_json`. Save each image
  to a file (decode base64; download URLs promptly, they expire) and report the paths.
- `X-MultiLLM-Auto-Selected-Model` and `X-MultiLLM-Auto-Attempts` say which provider
  answered and how many were tried.

## Generate a batch

One call for different prompts, sizes or models; each item succeeds or fails on its own.

```bash
curl -sS "$MULTILLM_BASE_URL/v1/images/batch" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" -H "Content-Type: application/json" \
  -d '{"defaults": {"model": "auto:image", "response_format": "url"},
       "items": [
         {"id": "hero", "prompt": "Mountain lake at dawn", "size": "3840x2160"},
         {"id": "icon", "prompt": "Flat lake icon, transparent background", "size": "1024x1024",
          "background": "transparent", "output_format": "png", "n": 2}]}'
```

At most 16 items. With `response_format: "url"` a batch returns up to 32 images,
otherwise 8 (base64 is large). Read `data[].status` (`succeeded` or `failed`),
`data[].images` and `data[].error`, and retry only the failed items.

## Generate a video

```bash
curl -sS "$MULTILLM_BASE_URL/v1/videos" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" -H "Content-Type: application/json" \
  -d '{"prompt": "A drone shot over a misty pine forest at sunrise", "seconds": 8,
       "aspect_ratio": "16:9", "resolution": "1080p"}'
```

- Returns `{"id": "video_…", "status": "queued"}`. Poll `GET /v1/videos/{id}` every 10 to
  15 seconds until `status` is `completed` or `failed`; clips usually take 1 to 5 minutes.
- Download `GET /v1/videos/{id}/content` (MP4) with the same key. A job belongs to the
  key that created it.
- `seconds` 1 to 20 (default 8; each provider uses its nearest supported length),
  `aspect_ratio` `16:9`, `9:16` or `1:1`, `resolution` `720p` or `1080p` (default),
  `image_url` (https or a PNG, JPEG or WebP data URL) to animate a still image, and
  `generate_audio` (default true where supported).

## Check providers

- `GET /v1/media/providers` lists each route's candidates, whether they can run now and
  their recent health, without generating anything.
- `POST /v1/media/probe` with `{"route": "auto:image"}` (admin key) generates one small
  low-quality image on every available candidate and reports which work. It spends about
  $0.01 to $0.04 per provider; run it only when asked.

## Costs and retries

- Images via GGUU cost a flat ¥0.04 each from 1K to 4K; OpenAI's `max` quality costs
  about $0.21 per image. Videos cost dollars per clip. Confirm with the user before
  generating videos or more than a few images unless they already asked for them.
- A provider error falls back automatically. A `504` or a response with
  `X-MultiLLM-Transport-Failure: timeout` means the request may already have been
  accepted and billed; it is not retried elsewhere. Tell the user, and retry only with
  their agreement.
- For a content-policy refusal, rephrase the prompt; do not cycle providers yourself.
- Prompts and reference images go to third-party providers. Keep secrets and personal
  data out of them.
