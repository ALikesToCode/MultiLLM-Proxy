# Moderation and OpenAI safety identifiers

`POST /v1/moderations` accepts the proxy API key with the `chat` scope.
It returns the provider's moderation response, including categories, scores,
and input types, without turning a flag into a generation policy.

Omitting `model` selects `auto:moderation`: OpenAI
`omni-moderation-latest`, then NavyAI for text. Route ordering can be edited
in Operations. Missing credentials and definite refusals can move to the next
candidate; timeouts and 5xx responses stop the route to avoid duplicate billing.
An explicit `provider:model` calls only that provider. Bare model names, as used
in OpenAI SDK examples, select OpenAI.

```json
{"model":"auto:moderation","input":["A first example.","A second example."]}
```

OpenAI and NanoGPT also accept a flat multimodal input:

```json
{
  "model": "openai:omni-moderation-latest",
  "input": [
    {"type":"text","text":"Describe the scene safely."},
    {"type":"image_url","image_url":{"url":"https://example.com/photo.png"}}
  ]
}
```

The gateway accepts up to 2,048 strings or content parts, a 32 MiB JSON body,
and 20 MiB per inline base64 image. Images use HTTPS URLs or PNG, JPEG, WebP,
or GIF data URLs. NavyAI accepts text only. NanoGPT moderation is paid;
discover current models and capabilities through
`GET /nanogpt/v1/moderation-models` before configuring it as a candidate.

## Inline OpenAI moderation

Native OpenAI Chat Completions and Responses requests can include
`"moderation":{"model":"omni-moderation-latest"}`.
Both unified explicit `openai:model` requests and provider-prefixed
`/openai/v1/chat/completions` and `/openai/v1/responses` routes preserve
OpenAI's input/output moderation signals and errors, including streaming signals.
Output moderation arrives after the full generation; it does not prevent content
already streamed from reaching the client.

Unified requests that would change protocol or use a different provider reject
inline moderation with HTTP 400. The gateway does not translate away the
moderation signal. Use the separate moderation endpoint for those workflows.
Image generation's existing `moderation: "auto" | "low"` field is a different
OpenAI setting.

For direct OpenAI generation, the gateway adds a stable opaque
`safety_identifier` to Chat Completions and Responses, and `user` to unified
image generation and edits, unless the caller supplied that field.
The value is an HMAC of the authenticated principal under the deployment's
Flask secret. Rotating that secret changes the identifier. Native JSON image
requests receive the same default; native multipart clients should supply
`user` themselves.

## Coverage

`sexual/minors` is a text-only moderation category. General moderation is not
a dedicated CSAM detector. Do not submit known or suspected CSAM imagery to this
endpoint; use an approved dedicated detection/reporting process.

Contracts were checked against the official
[OpenAI moderation guide](https://developers.openai.com/api/docs/guides/moderation),
[OpenAI safety guide](https://developers.openai.com/api/docs/guides/safety-best-practices),
[NavyAI moderation reference](https://api.navy/docs/moderations), and
[NanoGPT moderation reference](https://docs.nano-gpt.com/api-reference/endpoint/moderations).
Provider availability, model coverage and pricing can change.
