---
name: multillm-media
description: Generate and edit images, run image batches, make videos, and create embeddings, speech and transcriptions through MultiLLM-Proxy's media gateway, which picks the best current model and falls back to another provider when one fails. Use when a task needs a generated or edited picture, many pictures, a video clip, embeddings or audio.
---

# MultiLLM Media

Generate images and videos through the MultiLLM-Proxy gateway with one API key. The
gateway chooses the provider, falls back automatically, and keeps provider keys private.

Send `Authorization: Bearer $MULTILLM_API_KEY` from the user's private environment. Never
ask for the key in chat, print it, or save it in a repository. A key needs the `chat`
scope for images and video, `embeddings` or `audio` for those endpoints, and `admin` for
the provider probe.

## Choose a route

| Model | Use it for | Order tried |
| --- | --- | --- |
| `auto:image` | Best quality (the default) | GPT Image 2.5 Sunburst, Flare and GPT Image 2 via GGUU, Grok Imagine Image 2.0 via GGUU, GPT Image 2.5 Sunburst via Cloudflare AI, OpenAI, Grok Imagine via xAI, GPT Image 2 via Together, AIHubMix's free GPT Image 2, Leonardo Lucid Origin on Workers AI |
| `auto:image-fast` | Drafts and iteration | GPT Image 2.5 Flare first, then GPT Image 2 and Grok Imagine Image 2.0 via GGUU |
| `auto:gpt-image-2.5` | Only the GPT Image 2.5 family | GGUU, then Cloudflare AI, then OpenAI |
| `auto:image-edit` | Editing images (the default on `/v1/images/edits`) | GPT Image 2.5 Sunburst and GPT Image 2 via GGUU, GPT Image 2.5 Sunburst via Cloudflare AI and OpenAI, Grok Imagine Image 2.0 via xAI, AIHubMix's free GPT Image 2 |
| `auto:video` | Video clips | Veo 3.1 (Gemini API), Grok Imagine Video 1.5, Veo 3.1 on Cloudflare AI, Sora 2 Pro, Sora 2 |
| `auto:embed` | Embeddings | `text-embedding-3-small` from OpenAI, then NanoGPT (one model, so vectors stay comparable) |
| `auto:tts` | Speech | OpenAI `gpt-4o-mini-tts`, then Workers AI Aura |
| `auto:stt` | Transcription | OpenAI `gpt-4o-mini-transcribe`, NanoGPT, Together Whisper, Workers AI Whisper |

Use `provider:model` (for example `gguu:gpt-image-2.5-flare` or
`gguu-grok:grok-imagine-image-quality`) only when the user names a provider or model.
Operators can reorder routes in Operations.

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

### Large batches in the background

`POST /v1/images/batches` takes the same `items` and `defaults` but up to 500 items and
1,000 images, returns at once, and keeps running while you wait. Send an
`Idempotency-Key` header so a retried submission returns the same batch instead of a
second one, and an optional `webhook_url` (public HTTPS) to be notified when it ends.

```bash
curl -sS "$MULTILLM_BASE_URL/v1/images/batches" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" -H "Content-Type: application/json" \
  -H "Idempotency-Key: launch-images-1" \
  -d '{"defaults": {"model": "auto:image", "size": "1536x1024"},
       "items": [{"id": "hero", "prompt": "Mountain lake at dawn"},
                 {"id": "icon", "prompt": "Flat lake icon", "n": 2}]}'
```

Poll `GET /v1/images/batches/{id}` every 30 to 60 seconds until `status` is `completed`,
`cancelled` or `failed`, then page through `GET /v1/images/batches/{id}/results?limit=100`
(follow `next_after`); each item has `status`, `model` and `images` (signed links) or
`error`. `POST /v1/images/batches/{id}/cancel` stops queued items. `503
batches_not_configured` means this gateway has no background storage; use
`/v1/images/batch` instead.

## Edit an image

`POST /v1/images/edits` takes OpenAI's multipart form: `image` (or several `image[]`, PNG,
JPEG or WebP), an optional PNG `mask`, `prompt`, and optional `model` (default
`auto:image-edit`), `size`, `quality`, `n`, `background`, `output_format` and
`response_format`.

```bash
curl -sS "$MULTILLM_BASE_URL/v1/images/edits" -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -F image=@cat.png -F prompt="Put the cat in a spacesuit" -F response_format=url
```

JSON works too, with `images` as HTTPS or data URLs. To use pictures as references for a
new image instead, send `images` with `POST /v1/images/generations`. Send detailed PNGs as
they are; upload routes accept bodies up to 48 MiB.

To reuse a large source image across several requests, upload it once and pass its ID:

```bash
curl -sS "$MULTILLM_BASE_URL/v1/media/uploads" -H "Authorization: Bearer $MULTILLM_API_KEY" -F file=@reference.png
# then: -F image_file_id=mu_… in the multipart edit, or {"images": [{"file_id": "mu_…"}]} in JSON
```

Uploads last a day and only your key can use them. `503 media_storage_not_configured`
means this gateway has no storage; send the image in the request instead.

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

## Embeddings, speech and transcription

OpenAI-compatible bodies on `POST /v1/embeddings`, `POST /v1/audio/speech` and
`POST /v1/audio/transcriptions` (multipart `file`, up to 25 MiB). Omit `model` to use
`auto:embed`, `auto:tts` or `auto:stt`, or name a `provider:model`. For embeddings you
store, pin one model; vectors from different models cannot be compared. Python, with the
`client` from [Use from code](#use-from-code):

```python
vectors = client.embeddings.create(model="auto:embed", input=["first text", "second text"])
speech = client.audio.speech.create(model="auto:tts", voice="alloy", input="Build finished.")
pathlib.Path("done.mp3").write_bytes(speech.content)
text = client.audio.transcriptions.create(model="auto:stt", file=open("meeting.m4a", "rb")).text
```

These routes move to the next provider only after a refusal that proves no work was done;
a `5xx` or timeout is returned to you.

## Links to stored media

When the gateway stores media, image replies carry a gateway `url` of the form
`/v1/media/files/{file_id}?expires=…&signature=…` plus a `file_id`, and videos gain a
`file_id` and `content_url`. Signed links work without a key until they expire (seven
days by default). With the key, `GET /v1/media/files/{file_id}?format=json` returns a fresh
link and `DELETE /v1/media/files/{file_id}` removes the file. Without storage, replies
keep the provider's URLs, which expire sooner: download them promptly.

## Use from code

Python (OpenAI SDK; `quality="max"` and 4K sizes pass through even where the SDK's
type hints list fewer values):

```python
import base64, os, pathlib, time
import requests
from openai import OpenAI

base, key = os.environ["MULTILLM_BASE_URL"], os.environ["MULTILLM_API_KEY"]
client = OpenAI(base_url=base + "/v1", api_key=key, max_retries=0, timeout=600)

image = client.images.generate(model="auto:image", prompt="A paper lantern festival at dusk",
                               size="2048x2048", quality="max", response_format="b64_json")
pathlib.Path("lantern.png").write_bytes(base64.b64decode(image.data[0].b64_json))

headers = {"Authorization": f"Bearer {key}"}
batch = requests.post(f"{base}/v1/images/batch", headers=headers, timeout=900, json={
    "defaults": {"model": "auto:image", "response_format": "url"},
    "items": [{"id": "wide", "prompt": "Desert road at noon", "size": "3840x2160"},
              {"id": "square", "prompt": "Desert road icon", "size": "1024x1024"}]}).json()
for item in batch["data"]:
    print(item["id"], item["status"], [image["url"] for image in item.get("images", [])])

job = requests.post(f"{base}/v1/videos", headers=headers, timeout=900,
                    json={"prompt": "Waves rolling onto a black sand beach", "seconds": 8}).json()
while job["status"] not in ("completed", "failed"):
    time.sleep(15)
    job = requests.get(f"{base}/v1/videos/{job['id']}", headers=headers, timeout=60).json()
if job["status"] == "completed":
    video = requests.get(f"{base}/v1/videos/{job['id']}/content", headers=headers, timeout=600)
    pathlib.Path("waves.mp4").write_bytes(video.content)
```

TypeScript (`fetch`, so every gateway field is allowed):

```ts
const base = process.env.MULTILLM_BASE_URL!;
const headers = { Authorization: `Bearer ${process.env.MULTILLM_API_KEY}`, "Content-Type": "application/json" };

const response = await fetch(`${base}/v1/images/generations`, {
  method: "POST", headers,
  body: JSON.stringify({ model: "auto:image", prompt: "Isometric city block, soft light", size: "1536x1024", response_format: "url" }),
});
if (!response.ok) throw new Error(`Image failed: ${response.status} ${await response.text()}`);
const { data } = await response.json();
console.log(data[0].url, response.headers.get("X-MultiLLM-Auto-Selected-Model"));
```

Keep generation on the server (the key must not reach a browser), keep SDK retries at 0,
and allow long timeouts: `max` quality at 4K can take several minutes.

## Use as MCP tools

Coding agents connected to the MultiLLM MCP server (`$MULTILLM_BASE_URL/v1/mcp`, see the
`multillm-mcp` skill) get the same routes as tools: `generate_image` (1 to 4 images),
`generate_images_batch`, `create_video`, `get_video` and `media_providers`. They default to
`auto:image` or `auto:video` and `response_format: "url"`, make exactly one request per call
and never retry or poll. Inline images are limited to 5 MiB each and 10 MiB per call;
`get_video` returns `content_url`, never the MP4, so download it over HTTP with the same key.
Edits, background batches, embeddings and audio are HTTP-only: call them directly.

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
- A key may have a dollar budget or a model allowlist: `429 budget_exceeded` or
  `403 model_not_allowed` means stop and tell the user. `GET /v1/usage` shows the key's
  spend and remaining budget; check it before a large batch.
- Prompts and reference images go to third-party providers. Keep secrets and personal
  data out of them.
