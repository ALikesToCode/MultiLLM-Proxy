# Anthropic Claude API

Chat tool calls carry signed native assistant blocks in
`tool_calls[0].extra_content.anthropic.content`. Return that metadata unchanged
with the assistant message when submitting tool results. Streams deliver it on
the first tool call's index before the terminal chunk. This preserves thinking
signatures and redacted blocks required by Anthropic's tool continuation API.
Changed tool IDs, names, arguments or assistant text fail validation rather than
replaying stale native content.

Responses function calls retain the same metadata in
`extra_content.anthropic.content`. Return the complete `output` array unchanged
in the next request's `input`, followed by each `function_call_output`. For
streams, use `response.completed.response.output`; signed blocks can arrive
after an earlier tool item's done event when tools run in parallel.

Set `ANTHROPIC_API_KEY` in the server environment or Cloudflare Worker secrets.
The Worker forwards it to the Container. Restart the server, or deploy the
updated Worker and Container, after changing configuration.

## Spare keys and failover

Add spare keys as `ANTHROPIC_API_KEY_1`, `ANTHROPIC_API_KEY_2`, and so on:

```bash
npx wrangler secret put ANTHROPIC_API_KEY_1
```

Requests use the first key that is not resting, in that order, so the spare
carries traffic only after the primary is refused. When the Claude API refuses a
key, the gateway rests it and sends the same request once on the next key. This
applies to unified routes, native `/anthropic/v1/*` routes, and the
`auto:intelligence` chain. Refusals that rest a key:

| Response | Rest |
| --- | --- |
| 400 `invalid_request_error`, "Your credit balance is too low…" | 1 hour |
| 400 `invalid_request_error`, "You have reached your specified … API usage limits" | 1 hour |
| 429 with `error.details.error_code` `enforced_spend_limit_reached` | 1 hour |
| 402 `billing_error` | 1 hour |
| 401 `authentication_error` | 5 minutes |
| 429 rate limit | `retry-after`, or 1 minute, for that model |

These rests apply with `MODEL_COOLDOWN_ENABLED=true`, the production setting,
and are capped by `MODEL_COOLDOWN_MAX_SECONDS` (default 3600). A 403 can be
specific to one model, so it and other 400 errors return to the caller without
trying another key. A rested key returns to service when its rest ends. If every key
is resting, the request fails with 429 `model_cooldown`. Responses from unified
routes carry `X-MultiLLM-Credential-Attempts` with the number of keys tried.
`GET /admin/providers/usage` lists each key's slot name, whether it is the
active key or resting, and its dispatch and refusal counts; see
[provider usage](provider-usage.md#credential-slots).

Keys from different Anthropic organizations do not share thinking signatures:
a signed thinking block replays only in the organization that created it.
Prompt-cache affinity keeps a conversation on the key that served it, so a
conversation moves to the spare only when its key is refused. Its next request
may then fail with an invalid `signature` error; drop the earlier thinking
blocks, or start a new conversation. `ANTHROPIC_WORKSPACE_ID` is sent with every
key, so leave it empty when the keys belong to different organizations.

For a key that can act on multiple Anthropic workspaces, also set
`ANTHROPIC_WORKSPACE_ID` to the intended workspace. The server sends it as
`anthropic-workspace-id` for generation and model discovery. Caller headers
cannot change the configured workspace. A workspace-scoped key can omit this
setting. See the [Claude API authentication documentation](https://platform.claude.com/docs/en/api/overview.md).

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

## Advisor tool

Claude's [advisor tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/advisor-tool)
lets a stronger model advise while the request's model writes the answer. Send
it to `/v1/messages` with `anthropic-beta: advisor-tool-2026-03-01`:

```json
{"model": "anthropic:claude-haiku-5-5", "max_tokens": 2048,
 "tools": [{"type": "advisor_20260301", "name": "advisor", "model": "claude-sonnet-5-5",
            "max_uses": 1, "max_tokens": 1500}],
 "messages": [{"role": "user", "content": "..."}]}
```

The reply, streamed or not, passes through as Claude sent it, with its
`server_tool_use` and `advisor_tool_result` blocks. Append the whole `content`
to the next turn and keep the advisor tool in `tools` while the history holds
advisor results.

Claude bills the advisor's tokens at the advisor model's prices and reports
them only in `usage.iterations`, not in the top-level usage. The ledger prices
every step at its own model and records the advisor's steps under the advisor's
model; see [usage and budgets](usage-and-budgets.md#cost). Budgets and stream
cost caps count the advisor's worst case before the request is sent, so a key
with either must set `max_uses` and `max_tokens` (at least 1024) on the advisor
tool.

The advisor's model is held to the key's controls like the request's own model:
its allowlist, `official_only` and provider data class. A bare id such as
`claude-opus-5-5` is checked as its catalog id, `anthropic:claude-opus-5-5`, and
a key that may not use that model gets the same 403 `model_not_allowed` as a
request naming it directly, before anything reaches Claude. A model an operator
disabled gets the same 400 as naming it directly. On `/v1/messages` a catalog id
is accepted and sent to Claude as its bare id. The native route sends the request
as written, so use bare ids there. An advisor from another provider gets 400.
Forced provider preferences apply only to OpenRouter, so they do not change an
`anthropic:` advisor.

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
