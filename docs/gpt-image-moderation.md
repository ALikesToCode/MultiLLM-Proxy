# GPT Image moderation defaults

MultiLLM defaults GPT Image generation requests to the less restrictive
OpenAI-supported moderation level:

```json
{
  "moderation": "low"
}
```

The policy applies only to `POST /v1/images/generations` and native
`/{provider}/v1/images/generations` JSON requests whose model belongs to the
`gpt-image-1`, `gpt-image-1-mini`, `gpt-image-1.5`, or `gpt-image-2` family.
Versioned and relay-specific aliases such as `gpt-image-2-2026-04-21`,
`gpt-image-2-c`, `gpt-image-2-free`, and `openai/gpt-image-2` are included.

If the caller omits `moderation` or sends `null`, the proxy forwards `low`.
Explicit `low` and `auto` values are preserved. Any other value receives HTTP
`400` before an upstream generation is started.

Non-GPT image models such as Gemini Flash Image and Doubao Seedream are not
modified. Multipart image edits are also unchanged because the current OpenAI
Images edit contract does not expose the generation-only `moderation` field.

The same policy runs in both request layers:

- the Flask unified and native provider routes;
- the Cloudflare LinkAPI and Codex Everywhere fast paths.

JSON bodies that already contain an explicit supported moderation value retain
their original bytes on native routes. A missing default requires one JSON
normalization pass to insert `"moderation":"low"`. Multipart and binary bodies
remain byte-preserving.

Provider filtering still applies. `low` reduces moderation strictness; it does
not disable provider content policy or guarantee that a prompt will be
accepted.
