# Anthropic Claude API

Chat tool calls carry signed native assistant blocks in
`tool_calls[0].extra_content.anthropic.content`. Return that metadata unchanged
with the assistant message when submitting tool results. Streams deliver it on
the first tool call's index before the terminal chunk. This preserves thinking
signatures and redacted blocks required by Anthropic's tool continuation API.
Changed tool IDs, names, arguments or assistant text fail validation rather than
replaying stale native content.

Set `ANTHROPIC_API_KEY` in the server environment or Cloudflare Worker secrets.
The Worker forwards it to the Container. Restart the server, or deploy the
updated Worker and Container, after changing configuration.

Claude Haiku 5.5 is available in the built-in model catalog as
`anthropic:claude-haiku-5-5`. Refreshing the provider catalog discovers other
models available to the configured key. The upstream is fixed to
`https://api.anthropic.com`; caller proxy credentials are replaced with the
server's key in `x-api-key`.

## Unified API

Use a proxy API key and the provider-prefixed model ID on `/v1/chat/completions`,
`/v1/responses`, or `/v1/messages`. Chat and Responses requests are translated to
Claude Messages; native Messages requests retain their signed thinking blocks.

```bash
curl "$PROXY_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic:claude-haiku-5-5",
    "messages": [{"role": "user", "content": "Explain this repository"}],
    "reasoning_effort": "medium",
    "max_completion_tokens": 4096,
    "stream": true
  }'
```

For translated Haiku 5.5 requests, `reasoning_effort` uses adaptive thinking and
`output_config.effort`. Supported levels are `low`, `medium`, `high`, `xhigh`, and
`max`; `minimal` maps to `low`, and `none` disables thinking at `low` effort.
Manual thinking budgets become adaptive thinking. The proxy removes
`temperature`, `top_p`, and `top_k` from translated Haiku requests because the
model rejects common client sampling defaults. Native Messages requests keep
their original settings and receive Anthropic's validation errors.

Haiku 5.5 defaults to adaptive thinking at `medium` effort. Thinking consumes
output tokens, so leave room in `max_tokens` for both thinking and the answer.
The catalog advertises the model's 1,000,000-token context and 128,000-token
synchronous output limit; configured proxy request and token limits still apply.

## Native API

Native provider routes require an admin proxy key. Use `$PROXY_BASE_URL/anthropic`
as the Anthropic client's base URL and `claude-haiku-5-5` as its model ID.

| Operation | Route |
| --- | --- |
| Messages and streaming | `/anthropic/v1/messages` |
| Token counting | `/anthropic/v1/messages/count_tokens` |
| Model discovery | `/anthropic/v1/models` |

Send `x-api-key: $ADMIN_API_KEY` and `anthropic-version: 2023-06-01`.
`anthropic-beta` is forwarded when present. Native request bytes, signed thinking
blocks, response bodies, SSE events, status codes, and upstream errors pass
through. Generation requests use one transport attempt.

Haiku 5.5 rejects a final assistant prefill. End requests with a user turn, and
replay signed thinking blocks through the account that produced them.

References: [Haiku 5.5](https://platform.claude.com/docs/en/models/haiku-5-5/overview),
[migration guide](https://platform.claude.com/docs/en/models/haiku-5-5/migration-guide),
[effort](https://platform.claude.com/docs/en/build-with-claude/effort).
