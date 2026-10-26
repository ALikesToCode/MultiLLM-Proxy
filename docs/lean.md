# Lean endpoint

`/lean/v1/messages`, `/lean/v1/chat/completions` and `/lean/v1/responses` are the
unified routes with extra cost controls for models served by the Claude API
(`anthropic:` models). They are written for coding harnesses on Claude Haiku 5.5,
whose price depends on prompt length:

| Haiku 5.5, per million tokens | Prompt of 100,000 tokens or fewer | Longer prompt |
|---|---|---|
| Input | $0.10 | $0.50 |
| Cache read | $0.01 | $0.05 |
| Cache write (5 minutes) | $0.125 | $0.625 |
| Output | $0.50 | $2.50 |

The prompt length counts every input token, cache reads and writes included, and
a request one token over the limit pays the higher price on all of its tokens
([pricing](https://platform.claude.com/docs/en/about-claude/pricing#long-context-pricing)).
Lean mode keeps prompts cached and under that limit.

Requests to other providers behave exactly as on `/v1` and carry
`X-MultiLLM-Lean: inactive`. `/lean/v1/messages/count_tokens` and `/lean/v1/models`
are the `/v1` routes unchanged, so a harness can use one base URL.

## What lean mode does

Every change depends only on the request itself, so each later request of a
conversation repeats the earlier one's bytes up to its new turn. That keeps prompt
caching working, and keeps Haiku 5.5's replayed thinking blocks valid: Haiku 5.5
rejects a thinking block whose earlier conversation changed. Checked against the
Claude API: a second identical request read its whole 2,006-token prefix from the
cache, and a thinking block Haiku wrote through `/lean` was accepted when the next
turn replayed it through `/lean`, but rejected when the same turn went to `/v1`
with the raw shell output.

| Stage | Default | What it does |
|---|---|---|
| Prompt caching | on | Adds automatic caching (`cache_control` at the top level) and a breakpoint after the system prompt, or after the last tool when there is none. Skipped when the caller placed its own `cache_control`, as Claude Code does. |
| Tool result clearing | on, from 80,000 tokens | Adds `context_management` with `clear_tool_uses_20250919`: once the prompt passes the trigger, the API replaces old tool results with placeholders and keeps the 3 most recent, clearing at least 20,000 tokens at a time. The API applies it before the model reads the prompt, the harness keeps its full history, and it never invalidates thinking blocks. Skipped when the caller sends its own `context_management` or a compaction block. |
| Shell output | on | Results of shell tools (`Bash`, `bash`, `shell`, `exec_command`, `run_shell_command` and similar) lose ANSI escapes and progress-bar redraws; runs of four or more identical lines become one line and a count, and runs of blank lines become one. Other tools' results, file reads included, keep their exact bytes, so an edit tool can still match them. |
| Oversized results | 100,000 characters | A longer tool result keeps its first and last 50,000 characters with a marker in between. |
| Prompt limit | 99,000 tokens | A prompt estimated near the limit is counted with `count_tokens`, using the key that will send it, which reports its size before and after context editing. Anthropic calls the count an estimate that can differ slightly, so the default sits 1,000 tokens under the 100,000-token price line. Above the limit the request is refused with the error the harness treats as a full context window, so it compacts and retries instead of paying the higher price. The pricing page does not say whether the size before or after clearing picks the price, so by default the limit applies to the size before clearing; set `LEAN_PRICE_LIMIT_BASIS=cleared` once your bill shows that cleared prompts are priced by their smaller size. |
| Concise answers | off | Adds a short instruction to the system prompt: lead with the answer, no filler, code and commands exact. Turn it on with `LEAN_STYLE=concise` or per request with `X-MultiLLM-Lean-Style: concise` (`caveman` is accepted too). |

Lean mode never changes the model, effort, thinking settings or `max_tokens`.

### The refusal

| Route | Response |
|---|---|
| `/lean/v1/messages` | 400, Anthropic envelope, `invalid_request_error`, `prompt is too long: N tokens > 99000 maximum`. Claude Code compacts on this message. |
| `/lean/v1/chat/completions` | 400, `{"error": {"code": "context_length_exceeded", ...}}` with a message naming the maximum context length. |
| `/lean/v1/responses` with `stream: true` | A `response.failed` event with `context_length_exceeded`, the form Codex reads. Without streaming, the Chat Completions body above. |

When the prompt cannot be counted, the local estimate decides, and an estimate
above the limit is refused. That happens for URL and file sources, which
`count_tokens` rejects (lean estimates them at 1,600 tokens per image and 10,000
per document); for a request that replays thinking blocks alongside a server tool
such as web search, because `count_tokens` rejects server tools and dropping them
would fail its thinking-block check; and when a count fails, for example when
rate-limited. Such requests report `X-MultiLLM-Lean-Prompt-Count: estimate`, and
the limit is then a safety net, not a guarantee: the estimate can be low for a
URL document or an unusual tokenization. Without replayed thinking, server tools
are left out of the count and added back at 1,000 tokens each. A prompt with a
PDF is always counted, since its file size does not bound the text inside. A count
that refuses the key itself (401, 402 or 403) does not decide: the request goes
out so key rotation can rest that key and count again with the next one
(`X-MultiLLM-Lean-Prompt-Count: skipped`). If compacting cannot bring a
prompt under the limit, for example because the newest message alone is larger,
the harness reports the error: Claude Code stops after three failed compactions.

### Response headers

| Header | Meaning |
|---|---|
| `X-MultiLLM-Lean` | `applied` for a Claude API request, `inactive` for other providers |
| `X-MultiLLM-Lean-Rules` | Version of the rules above |
| `X-MultiLLM-Lean-Stages` | Stages that changed the request, for example `cache,clear-tool-uses,condense-shell` |
| `X-MultiLLM-Lean-Prompt-Tokens` | Prompt size the limit was checked against: counted by the API near the limit, otherwise a rough local estimate |
| `X-MultiLLM-Lean-Prompt-Count` | `provider`, `estimate`, or `skipped` when the count refused the key |
| `X-MultiLLM-Lean-Prompt-Tokens-After-Clearing` | Counted size after context editing, when it differs |
| `X-MultiLLM-Lean-Condensed-Chars` | Characters removed from tool results |

The API reports what it cleared in the response's `context_management` field and
cache use in `usage.cache_read_input_tokens` and `usage.cache_creation_input_tokens`.

## Harness setup

Set each harness to compact before 100,000 tokens, so the refusal stays a safety
net.

### Claude Code

```bash
export ANTHROPIC_BASE_URL="$PROXY_BASE_URL/lean"
export ANTHROPIC_API_KEY="$MULTILLM_API_KEY"
export ANTHROPIC_MODEL="anthropic:claude-haiku-5-5"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="anthropic:claude-haiku-5-5"
export CLAUDE_CODE_AUTO_COMPACT_WINDOW=100000
claude
```

Claude Code places its own cache breakpoints, so lean mode leaves caching to it.

### Codex

```toml
model = "anthropic:claude-haiku-5-5"
model_provider = "multillm-lean"
model_context_window = 100000
model_auto_compact_token_limit = 85000

[model_providers.multillm-lean]
name = "MultiLLM lean"
base_url = "https://multillm-proxy.cserules.workers.dev/lean/v1"
env_key = "MULTILLM_API_KEY"
wire_api = "responses"
```

### opencode

```json
{
  "provider": {
    "multillm-lean": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://multillm-proxy.cserules.workers.dev/lean/v1",
        "apiKey": "{env:MULTILLM_API_KEY}"
      },
      "models": {
        "anthropic:claude-haiku-5-5": { "limit": { "context": 100000, "output": 32000 } }
      }
    }
  }
}
```

Chat Completions and Responses requests reach the Claude API translated, and the
translation drops caller `cache_control`, so for Codex and opencode lean mode's
caching is what makes cache reads happen at all.

## Settings

| Variable | Default | |
|---|---|---|
| `LEAN_ENDPOINT_ENABLED` | `true` | `false` stops serving `/lean` |
| `LEAN_PROMPT_TOKEN_LIMIT` | `99000` | `0` turns the refusal off |
| `LEAN_PRICE_LIMIT_BASIS` | `original` | `cleared` applies the limit to the prompt after context editing |
| `LEAN_CLEAR_TRIGGER_TOKENS` | `80000` | `0` turns tool result clearing off |
| `LEAN_CLEAR_KEEP_TOOL_USES` | `3` | Recent tool uses that are never cleared |
| `LEAN_CLEAR_AT_LEAST_TOKENS` | `20000` | Minimum cleared per edit, so a cache rewrite is worth it |
| `LEAN_CLEAR_EXCLUDE_TOOLS` | empty | Comma-separated tool names whose results are never cleared |
| `LEAN_CACHE_TTL` | `5m` | `1h` for sessions with long pauses; 1-hour writes cost 2x input |
| `LEAN_CONDENSE_SHELL_OUTPUT` | `true` | |
| `LEAN_TOOL_RESULT_MAX_CHARS` | `100000` | `0` turns clipping off |
| `LEAN_STYLE` | `none` | `concise` adds the concise-answer instruction |

Keep a conversation on one base URL and its settings fixed. Lean mode sends shell
output condensed, so moving a conversation between `/v1` and `/lean`, or changing
`LEAN_CONDENSE_SHELL_OUTPUT`, `LEAN_TOOL_RESULT_MAX_CHARS` or `LEAN_STYLE` partway
through, changes bytes the model already saw. On accounts created on or after
31 August 2026 the next request that replays a thinking block then fails with
``Invalid `signature` in `thinking` block. The block is bound to a different
conversation``; start a new conversation. The cache and clearing settings change
only cost: one cache rewrite.

## Notes

- Cleared tool results are gone for the model, not for the harness: if the model
  needs one again it reruns the tool.
- The Claude API's prompt cache belongs to the account. The key pool keeps using
  the first key until it is refused ([key failover](anthropic.md#spare-keys-and-failover)); a conversation
  that moves to the spare key starts with a cold cache, and its earlier thinking
  blocks are dropped rather than rejected.
- Research behind these choices, including what Claude Code, Codex, opencode,
  Cline and Gemini CLI do, is summarised in the pull request that added this
  page.
