# Image and video generation

MultiLLM serves the leading image and video models behind automatic routes that try
providers in order and fall back when one fails. Agents can learn the API from
`/agent-onboarding/media/SKILL.md` (linked from `/llms.txt`).

## Routes

The seeded routes follow the Artificial Analysis text-to-image arena (September 2026):
GPT Image 2.5 Sunburst (Elo 1196) and Flare (1190) lead, then GPT Image 2 (1171) and Grok
Imagine Image 2.0 (1155). GGUU serves all four first because its public price is a flat
¥0.04 per image at 1K, 2K and 4K, against about $0.21 for Sunburst at `max` from OpenAI.
OpenRouter is not used.

| Route | Candidates in order |
| --- | --- |
| `auto:image` | `gguu:gpt-image-2.5-sunburst`, `gguu:gpt-image-2.5-flare`, `gguu:gpt-image-2`, `gguu-grok:grok-imagine-image-2.0`, `cloudflare:openai/gpt-image-2.5-sunburst`, `openai:gpt-image-2.5-sunburst`, `xai:grok-imagine-image-2.0`, `together:openai/gpt-image-2`, `aihubmix:gpt-image-2-free`, `cloudflare:@cf/leonardo/lucid-origin` |
| `auto:image-fast` | `gguu:gpt-image-2.5-flare`, `gguu:gpt-image-2`, `gguu-grok:grok-imagine-image-2.0`, `cloudflare:openai/gpt-image-2.5-flare`, `openai:gpt-image-2.5-flare`, `xai:grok-imagine-image-2.0`, `cloudflare:@cf/black-forest-labs/flux-1-schnell` |
| `auto:gpt-image-2.5` | `gguu:gpt-image-2.5-sunburst`, `gguu:gpt-image-2.5`, `gguu:gpt-image-2.5-flare`, `cloudflare:openai/gpt-image-2.5-sunburst`, `openai:gpt-image-2.5-sunburst`, `openai:gpt-image-2.5-flare` |
| `auto:image-edit` | `gguu:gpt-image-2.5-sunburst`, `gguu:gpt-image-2`, `cloudflare:openai/gpt-image-2.5-sunburst`, `openai:gpt-image-2.5-sunburst`, `xai:grok-imagine-image-2.0`, `aihubmix:gpt-image-2-free` |
| `auto:video` | `gemini:veo-3.1-generate-preview`, `xai:grok-imagine-video-1.5`, `cloudflare:google/veo-3.1`, `openai:sora-2-pro`, `openai:sora-2` |

A candidate without a credential (or Cloudflare AI without its binding) is skipped before
any request. Operators reorder or extend routes in **Operations**; the order is stored in
D1 ([control-plane storage](control-plane-storage.md#automatic-routes-in-d1)). A stored route
that still holds an earlier seeded default follows the current default.

GGUU API keys belong to a group, so GGUU appears as two providers. `gguu` uses a
`gpt-image` group key (`GGUU_API_KEY`) for the GPT Image models; `gguu-grok` uses a
`Grok-image` group key (`GGUU_GROK_API_KEY`, alias `GGUUAI_API_KEY_GROK`) for
`grok-imagine-image-2.0` and `grok-imagine-image-quality`. A provider without its key is
skipped. Batch image generation through GGUU's own `/v1/images/batches` API needs a
group with batch generation enabled.

## Images

`POST /v1/images/generations` takes the OpenAI Images body. On automatic routes:

- `quality` defaults to `max`. Every candidate receives the closest settings its model
  supports: GPT Image 2.5 accepts `low` to `max`; GPT Image 2 and 1.5 top out at `high`;
  Grok Imagine Image 2.0 takes `low` or `medium` with `aspect_ratio` and a `2k`
  `resolution` instead of `size`; Cloudflare's GPT Image adapter accepts the three
  standard sizes; Workers AI models turn quality into diffusion steps.
- `size` is `auto` or `WIDTHxHEIGHT` with edges up to 3840 that are multiples of 16 and a
  ratio of at most 3:1. Larger requests are scaled down for models with lower limits.
- `n` from 1 to 10 sends one request per image, up to four at a time, and merges the
  results; `X-MultiLLM-Images-Returned` reports how many succeeded.
- Image requests allow ten minutes per provider, because `max` quality at 4K can take
  several minutes.

### Failover

Any HTTP error from a provider means it delivered no image, so the next candidate runs,
including 5xx errors and content-policy refusals. A request that never connected also
moves on. A timeout or a dropped connection after the request was sent does not: that
generation may already be billed, so the route stops with `504` and
`X-MultiLLM-Transport-Failure: timeout` (or `interrupted`). Chat routes keep their
stricter rule, which only moves on after refusals.

### Edits and reference images

`POST /v1/images/edits` takes OpenAI's multipart form: `image` (or `image[]`, up to 16
PNG, JPEG or WebP files of at most 20 MiB each and 30 MiB together), an optional PNG
`mask` (at most 4 MiB, applied to the first image), `prompt`, `model` (default
`auto:image-edit`), `size`, `quality`, `n`, `background`, `output_format`,
`output_compression`, `input_fidelity` and `response_format`. JSON works too, with the
images as HTTPS or data URLs:

```json
{"model": "auto:image-edit", "prompt": "Put the cat in a spacesuit",
 "images": ["https://example.com/cat.png", {"image_url": "data:image/png;base64,..."}]}
```

The Worker downloads HTTPS images (public hosts only, at most three redirects), so a URL
never reaches the Container's private network. A `POST /v1/images/generations` body with
`images` is sent the same way: the images become references for the models that accept
them, and other candidates of the route are skipped.

Each provider receives the edit in its own format. OpenAI, AIHubMix, LinkAPI and the image
relays (GGUU's GPT Image group and the others with edits enabled) take OpenAI's form.
xAI takes JSON image URLs, at most three and no mask. Cloudflare's GPT Image models take
up to 16 images (16 MiB in total) and no mask. Settings are translated as for
generation, without `moderation`. A candidate that cannot take the request is skipped
before anything is sent; after that the failover rule above applies.

### Batches

`POST /v1/images/batch` runs different prompts, sizes and models in one call:

```json
{
  "defaults": {"model": "auto:image", "response_format": "url"},
  "items": [
    {"id": "hero", "prompt": "Mountain lake at dawn", "size": "3840x2160"},
    {"id": "icon", "prompt": "Flat lake icon", "size": "1024x1024", "n": 2}
  ]
}
```

Items inherit `defaults` and default to `auto:image`. A batch takes up to 16 items and
returns up to 32 images with `response_format: "url"`, or 8 with base64. Up to four
images generate at a time, each through its route's failover. The reply lists every item
with `status` (`succeeded` or `failed`), its `images` or `error`, and the model that
served it, plus a `summary`. A batch counts as one request against rate limits.

## Video

Video is asynchronous:

1. `POST /v1/videos` with `prompt` and optionally `model` (default `auto:video`),
   `seconds` (1 to 20, default 8), `aspect_ratio` (`16:9`, `9:16`, `1:1`), `resolution`
   (`720p` or `1080p`, default `1080p`), `image_url` (https or a PNG, JPEG or WebP data URL)
   and `generate_audio` (default true). The reply is a job with a `video_…` ID.
2. `GET /v1/videos/{id}` returns `queued`, `in_progress`, `completed` or `failed`, and a
   `content_url` once completed.
3. `GET /v1/videos/{id}/content` streams the MP4.

The route falls back only while creating the job, under the image rule above. Each
provider receives its nearest supported settings: Veo lengths are 4, 6 or 8 seconds,
Sora 4, 8 or 12 at 1280x720 (Sora 2 Pro at 1792x1024 for 1080p), and Grok up to 15.
Veo through the Gemini API takes still images only as data URLs. Cloudflare's Veo
returns the finished clip when the create request ends, so that request can take
several minutes.

Job IDs are signed with `FLASK_SECRET_KEY` (or `JWT_SECRET`) and name the provider job
and the key's user. The Container keeps no job state, so jobs survive restarts, and
another key gets `404`. Without either secret, jobs last only until the Container
restarts.

## Cloudflare AI

`wrangler.jsonc` binds `AI`. The Worker exposes it to the Container as
`http://ai.internal`, so no Cloudflare token reaches the Container. Third-party models
(`openai/gpt-image-*`, `google/veo-3.1`) run through AI Gateway (the gateway named by the
optional `AI_GATEWAY_ID` Worker variable, default `default`) with Unified Billing and
zero data retention; they need AI Gateway credits. `@cf/` models run on Workers AI.
Cloudflare candidates are skipped when the binding is absent.

## Checking providers

- `GET /v1/media/providers` lists every media route's candidates with `available`
  (credential or binding present, model enabled), the provider circuit state and its
  last status. It never generates anything.
- `POST /v1/media/probe` with `{"route": "auto:image"}` needs an admin key. It generates
  one 1024x1024 `low` quality image on each available candidate, one at a time, and
  reports `status`, `seconds`, `error` and the `working` list. Expect to spend about
  $0.01 to $0.04 per candidate. Videos are not probed because each clip costs dollars;
  test them with one `POST /v1/videos`.
