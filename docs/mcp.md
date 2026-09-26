# MultiLLM MCP server

Coding agents can use the gateway's model discovery, chat and media generation as MCP
tools. The server lives at `/v1/mcp`; the [Knowledge MCP](knowledge-agents.md) keeps
`/mcp`. Agents can install the [`multillm-mcp` skill](../skills/multillm-mcp/SKILL.md),
served at `/agent-onboarding/mcp/SKILL.md`, and read `/agent-onboarding/mcp/config.json`
for the endpoint, protocol versions, scopes and tool list.

## How it works

Each `tools/call` becomes exactly one request to the matching REST route inside the
Container (`routes/gateway_mcp.py` dispatches it through Flask with the caller's own key
and a fresh request context). Authentication, scopes, integration-key policy, rate limits
and allowances, automatic-route fallback, free-pool rules and metrics are therefore the
REST ones, and REST changes reach MCP without a second implementation. The MCP envelope
itself reserves no rate-limit slot; the inner request does. Nothing is retried, polled,
cached or stored, and generated images and videos are never saved on the server.

| Tool | REST route | Scope | Cost | Annotations |
| --- | --- | --- | --- | --- |
| `list_models` | `GET /v1/models` | `models` | free | read-only, closed world |
| `chat` | `POST /v1/chat/completions` | `chat` | paid unless `free:text` / `free:vision` | not read-only |
| `generate_image` | `POST /v1/images/generations` | `chat` | paid | not read-only |
| `generate_images_batch` | `POST /v1/images/batch` | `chat` | paid | not read-only |
| `create_video` | `POST /v1/videos` | `chat` | paid, dollars per clip | not read-only |
| `get_video` | `GET /v1/videos/{id}` | `chat` | free | read-only, idempotent |
| `media_providers` | `GET /v1/media/providers` | `chat` | free | read-only, closed world |

Paid tools are not marked read-only, so clients that auto-approve read-only tools still ask
before calling them, and their descriptions start with `PAID`.

- `list_models` returns compact entries (`id`, `provider`, `chat`, `images`, `video`,
  `tools`, `vision`, `status`, and `context_window`, `max_output_tokens`,
  `input_cost_per_million`, `output_cost_per_million` when known). `tools` and `vision` are
  `true` or `false` only when the catalog confirms it, otherwise `null`. Filters: `kind`
  (`chat`, `images`, `video`), `provider`, `free`, `tools`, `vision`, `search` (ID
  substring) and `limit` (1 to 500, default 100) with `total` and `truncated`.
- `chat` takes `model` (default `free:text`), `prompt` or `messages` (not both), `system`,
  `max_tokens` (default 4096), `temperature` and `response_format`. It never streams and
  accepts no tools, plugins or routing overrides. It returns `content`, `finish_reason`,
  `usage`, `selected_model` and `gateway`; answers longer than 200,000 characters are cut
  with `truncated: true`.
- `generate_image` takes `prompt`, `model` (default `auto:image`), `n` (1 to 4), `size`,
  `quality`, `background`, `output_format` and `response_format` (default `url`).
  `generate_images_batch` takes up to 16 `items` and `defaults` (default model
  `auto:image`, format `url`). URLs are returned as they come; base64 images become MCP
  `image` blocks of at most 5 MiB each and 10 MiB per call (PNG, JPEG, WebP or GIF, checked
  by signature). Larger or unrecognized images are listed with `omitted` and their size.
- `create_video` takes `prompt`, `model` (default `auto:video`), `seconds`, `aspect_ratio`,
  `resolution`, `image_url` and `generate_audio`. `get_video` returns the job status and,
  once completed, `content_url` and `content_path` for an HTTP download with the same key;
  it never returns video bytes. Jobs belong to the key that created them.

Every result has `structuredContent` and the same JSON as a text block (images come
first). `gateway` carries the inner HTTP status and, when present, the provider, model,
selected model, attempts, estimated cost, `Retry-After`, transport failure and request
ID. A REST error becomes `isError: true` with `error.status`, `error.code`,
`error.message`, provider `details` and `retried: false`; a `502`, `504` or a timeout
transport failure adds a `billing_note` telling the agent to ask before repeating the call.
Invalid arguments are validated against the tool's input schema and returned as
`invalid_arguments` without calling the gateway.

## Protocol

Stateless Streamable HTTP, matching the Knowledge MCP: `POST` only (`GET` and `DELETE`
return `405`), JSON replies without a session or event stream, JSON-RPC requests of at most
1 MiB with duplicate keys and non-finite numbers rejected. The server negotiates
`2025-06-18` (the version the Knowledge MCP offers; `2025-03-26` is not offered because it
requires batching) and rejects another `MCP-Protocol-Version` header with `400`. Send
`Accept: application/json, text/event-stream`; clients that accept only JSON also work.
Notifications and replies to server requests get `202` with no body. Methods:
`initialize`, `ping`, `tools/list` and `tools/call`; anything else is `-32601`, an unknown
tool `-32602`. `tools/list` shows only the tools the key's scopes allow; a call without
the scope returns an `insufficient_scope` tool error.

Authenticate with `Authorization: Bearer <proxy key>` (or `X-MultiLLM-Api-Key`). A key
with `chat` or `models` opens the endpoint; a key with neither gets `403`, and admin keys
have both. Durable integration keys stay limited to intelligence routing and cannot use
this endpoint. Browser requests from another origin are refused with `403`. The Worker
forwards `/v1/mcp` to the Container like other `/v1` routes; the Knowledge edge handles
only `/mcp` and `/v1/knowledge/*`.

## Connect a client

Keep the key in the environment (`MULTILLM_API_KEY`); every example references it.

```bash
# Claude Code: project .mcp.json; single quotes keep ${...} for Claude Code to expand.
claude mcp add --transport http multillm "$MULTILLM_BASE_URL/v1/mcp" --scope project \
  --header 'Authorization: Bearer ${MULTILLM_API_KEY}'

# Codex
codex mcp add multillm --url "$MULTILLM_BASE_URL/v1/mcp" --bearer-token-env-var MULTILLM_API_KEY
```

```toml
# ~/.codex/config.toml
[mcp_servers.multillm]
url = "https://gateway.example/v1/mcp"
bearer_token_env_var = "MULTILLM_API_KEY"
tool_timeout_sec = 600
```

```json
{"mcpServers": {"multillm": {"url": "https://gateway.example/v1/mcp",
  "headers": {"Authorization": "Bearer ${env:MULTILLM_API_KEY}"}}}}
```

The last block is Cursor's `.cursor/mcp.json`. `max` quality images and some video
providers take minutes, so raise the client's tool timeout (Codex `tool_timeout_sec`,
Claude Code `MCP_TOOL_TIMEOUT` in milliseconds).

## Check by hand

```bash
MCP="$MULTILLM_BASE_URL/v1/mcp"
AUTH="Authorization: Bearer $MULTILLM_API_KEY"
curl -sS "$MCP" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
curl -sS "$MCP" -H "$AUTH" -H 'Content-Type: application/json' -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
curl -sS "$MCP" -H "$AUTH" -H 'Content-Type: application/json' -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_models","arguments":{"free":true}}}'
```

`list_models` and `media_providers` cost nothing. `chat` with `free:text` uses only free
models. Tests: `python -m pytest -q tests/test_gateway_mcp.py` and
`node --test tests/test_gateway_mcp_worker.mjs`.
