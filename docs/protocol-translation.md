# Protocol translation

The unified API speaks three wire protocols:

| Route | Protocol |
| --- | --- |
| `POST /v1/chat/completions` | OpenAI Chat Completions |
| `POST /v1/responses` | OpenAI Responses |
| `POST /v1/messages` | Anthropic Messages |
| `POST /v1/messages/count_tokens` | Anthropic token count (local estimate) |

Any route accepts any `provider:model`, `auto:*` route, `free:*` pool or
`auto:intelligence`. When the selected model speaks the caller's protocol the
request passes through unchanged; otherwise it is translated statelessly, sent
to the model's native endpoint, and the answer is translated back, including
event-by-event streams. Chat Completions is the pivot: a Responses request for a
Messages-only model is translated Responses to Chat to Messages and back.

The translators live in `services/protocol_translation/`. Their current
event schemas follow the
[Anthropic streaming reference](https://platform.claude.com/docs/en/build-with-claude/streaming)
and the [OpenAI Responses streaming events](https://developers.openai.com/api/reference/resources/responses/streaming-events).

## Which model speaks what

`providers/protocols.py` declares native protocols as data:

- `PROVIDER_NATIVE_ENDPOINTS` lists providers whose whole catalog also accepts
  Responses or Messages (`codex-easy`, `linkapi`: Responses; `nanogpt`,
  `navyai`: Responses and Messages). Every other provider speaks Chat
  Completions.
- `MODEL_ENDPOINT_RESOLVERS` maps a provider to a per-model resolver. OpenCode
  uses `opencode_model_endpoint`, so `opencode:grok-4.6` is Responses-only and
  `opencode:minimax-m3` is Messages-only.

To declare another provider, add it to one of these tables. `GET /v1/models`
reports these OpenCode models with `supports_chat: true`, and
`provider_metadata.api_endpoint`/`api_protocol` still name the native protocol.

## Routing rules

| Request | Selected model | Behaviour |
| --- | --- | --- |
| Chat | speaks Chat | Unchanged (existing behaviour) |
| Chat | Responses- or Messages-only | Translated to its native endpoint |
| Responses or Messages | explicit model that speaks it | Native passthrough |
| Responses or Messages | explicit model that does not | Translated through Chat |
| Responses or Messages | `auto:*`, `free:*`, `auto:intelligence`, `routing` | Translated to Chat and dispatched by the normal Chat dispatcher |

Automatic routes keep their own failover rules, because the translated request
runs through the same Chat dispatcher: candidates are tried in order and a
translated error keeps its status code, so `401`, `402`, `403`, `404`, `429` and
an open circuit still move to the next candidate while any other failure is
returned unchanged. `X-MultiLLM-Auto-Route`, `X-MultiLLM-Auto-Selected-Model`,
`X-MultiLLM-Auto-Attempts` and `X-MultiLLM-Auto-Selected-Priority` are kept.
An automatic route whose candidates only generate images or video returns
`400` on `/v1/responses` and `/v1/messages`.

NanoGPT in subscription-only mode and Kimi Code are exceptions kept from the
Responses route: NanoGPT then uses the Chat bridge instead of its native
endpoints, and an explicit `kimi-code:*` model is rejected on `/v1/responses`.

`/optimize/v1/chat/completions` uses the same Chat dispatcher, so optimized
requests reach Responses- and Messages-only models too.

## Coverage

| Feature | Chat ↔ Messages | Chat ↔ Responses |
| --- | --- | --- |
| System prompts | `system`/`developer` messages ↔ top-level `system` (joined in order) | `system`/`developer` messages ↔ `instructions` and system input items; `developer` becomes `system` in Chat |
| Multi-turn text | Consecutive same-role turns are merged | Message items ↔ messages |
| Images | Data URL ↔ `base64` source, URL ↔ `url` source | `image_url` ↔ `input_image` |
| Files | Inline base64 PDF `file` part ↔ `document`; text documents become text | `file` ↔ `input_file` |
| Tools | `function` tools ↔ custom tools with `input_schema` | `function` tools ↔ flat function tools (`strict: false` unless set) |
| Tool calls and results | `tool_calls` ↔ `tool_use`; `tool` messages ↔ `tool_result` blocks placed first in the user turn; tool-result images follow in a user message; `is_error` prefixes `Error:` | `tool_calls` ↔ `function_call` items; `tool` messages ↔ `function_call_output` |
| `tool_choice` | `auto`/`none` ↔ same, `required` ↔ `any`, function ↔ `tool`; `parallel_tool_calls: false` ↔ `disable_parallel_tool_use` | `auto`/`none`/`required` and function; `allowed_tools` filters the tool list |
| Structured output | `json_schema` ↔ `output_config.format`; `json_object` adds a JSON-only system instruction | `response_format` ↔ `text.format` |
| Stop sequences | `stop` ↔ `stop_sequences` | Dropped: Responses has none |
| Max tokens | `max_tokens`/`max_completion_tokens` ↔ `max_tokens` (Messages default 8192) | ↔ `max_output_tokens` |
| Temperature, `top_p` | Temperature is clamped to 0–1 for Messages | Passed through |
| Reasoning | `reasoning_effort` → `thinking` with a budget (low 2048 … max 32768, kept below `max_tokens`, dropped under 1024); `none` disables thinking. `thinking` budgets and `output_config.effort` → `reasoning_effort` | `reasoning_effort` ↔ `reasoning.effort` |
| Reasoning output | `thinking` blocks ↔ `reasoning_content` | `reasoning` items (`reasoning_text` or summaries) ↔ `reasoning_content` |
| Usage | Anthropic input excludes cache reads and writes; both are kept (`cached_tokens`, `cache_write_tokens`) | `input_tokens_details`/`output_tokens_details` ↔ `prompt_tokens_details`/`completion_tokens_details` |
| Stop reasons | `end_turn`/`stop_sequence`/`pause_turn` → `stop`, `max_tokens`/`model_context_window_exceeded` → `length`, `tool_use` → `tool_calls`, `refusal` → `content_filter` | `incomplete` with `max_output_tokens` → `length`, `content_filter` → `content_filter` |
| Errors | Anthropic `{"type":"error","error":{...}}` ↔ OpenAI `{"error":{...}}`, status kept | Both use the OpenAI envelope and pass through |

Reasoning is round-tripped only where the target can use it: thinking chat
models such as Kimi and DeepSeek need `reasoning_content` back on assistant
tool-call turns, so it is sent there and dropped elsewhere. Translated thinking
blocks carry an empty `signature`; they are removed before a request is passed
natively to a Messages model.

### Dropped safely

Chat: `logprobs`, `top_logprobs`, `logit_bias`, penalties, `seed`,
`service_tier`, `prompt_cache_key`, `metadata`. Messages: `metadata.user_id`
(free pools reject `user`), `cache_control`, `top_k`, citations,
`context_management`, `anthropic-version` and `anthropic-beta` (ignored when the
target does not speak Messages). Responses: `store` (responses are never
stored; translated requests send `store: false`), `include`, `truncation`,
`text.verbosity`, `metadata`, `prompt_cache_key`. Server-tool history blocks in
Messages conversations are dropped.

### Rejected with 400

These need server-side state or a provider runtime the route cannot reproduce:

- Responses: `previous_response_id`, `conversation`, `background`, `prompt`,
  `item_reference` input items, built-in tools (`web_search`, `file_search`,
  `code_interpreter`, `computer_use_preview`, `image_generation`, `mcp`,
  `local_shell`, custom tools) and built-in tool history items or tool choices.
- Messages: `container`, `mcp_servers`, and every typed Anthropic tool
  (`web_search_*`, `web_fetch_*`, `code_execution_*`, `bash_*`,
  `text_editor_*`, `computer_*`, `memory_*`, tool search). File-ID images and
  documents, and URL documents.
- Chat into Messages or Responses: `n` above 1, audio output, legacy
  `functions`, audio input parts.

The 400 body is an OpenAI error envelope with `param` naming the field; on
`/v1/messages` it is Anthropic's `invalid_request_error`. Native passthrough
routes do not apply these checks.

## Streaming

Streams are translated event by event without buffering: each upstream SSE
event is parsed as it arrives and written as the target's events.

- Chat targets receive `chat.completion.chunk` frames, a final chunk with
  `finish_reason` and `usage`, then `data: [DONE]`.
- Messages targets receive `message_start`, sequential content blocks
  (`thinking`, `text`, `tool_use` with `input_json_delta`), `message_delta` with
  the stop reason and cumulative usage, and `message_stop`.
- Responses targets receive `response.created`, `response.in_progress`, output
  item and content part events (`response.output_text.delta`,
  `response.reasoning_text.delta`, `response.function_call_arguments.delta`),
  and `response.completed` or `response.incomplete`, with increasing
  `sequence_number`.

Provider keep-alive comments and Anthropic `ping` events are forwarded as SSE
comments, and translated streams keep `Content-Type: text/event-stream`, so the
Worker's idle heartbeat (`SSE_STREAM_HEARTBEAT_MS`) still applies.

A stream is complete only when it reaches its terminal event (`message_stop`,
`response.completed`/`response.incomplete`, or a Chat `finish_reason`). If the
upstream ends early or the connection breaks, the translated stream ends with a
well-formed terminal event that marks it unfinished, never a fake success:

| Target | Upstream ended early | Upstream sent an error |
| --- | --- | --- |
| Chat | `{"error":{"code":"stream_interrupted",...}}` then `[DONE]` | `{"error":{...}}` then `[DONE]` |
| Messages | `event: error` with `api_error` | `event: error` with the mapped type |
| Responses | `response.incomplete` with `incomplete_details.reason: "upstream_interrupted"` | `error` then `response.failed` |

`upstream_interrupted` is a MultiLLM value outside OpenAI's documented reasons.
When a model answers a streaming request with JSON, or a non-streaming request
with SSE, the body is replayed or folded so the caller receives the mode it
asked for.

## Anthropic Messages endpoint

`POST /v1/messages` authenticates with `x-api-key` or `Authorization: Bearer`
(or `X-MultiLLM-Api-Key`) using the normal proxy keys and the `chat` scope.
`anthropic-version` and `anthropic-beta` are accepted and never required. Every
non-streamed error on `/v1/messages`, including authentication, rate-limit and
validation errors, uses Anthropic's error envelope.

`POST /v1/messages/count_tokens` returns `{"input_tokens": N}` from a local
estimate (about four characters per token, the gateway's rate-limit
heuristic), marked with `X-MultiLLM-Token-Count: estimate`. It makes no
provider call and is not the target model's tokenizer.

### Claude Code

```bash
export ANTHROPIC_BASE_URL="$PROXY_BASE_URL"
export ANTHROPIC_API_KEY="$MULTILLM_API_KEY"
export ANTHROPIC_MODEL="auto:glm-5.2"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="opencode:minimax-m3"
claude
```

`ANTHROPIC_AUTH_TOKEN` works instead of `ANTHROPIC_API_KEY` (it is sent as a
Bearer token). Model names are MultiLLM IDs. Claude Code's web search and other
Anthropic server tools are unavailable unless the model is a native Messages
model that provides them. Following Claude Code's
[gateway protocol reference](https://code.claude.com/docs/en/llm-gateway-protocol):

- Claude Code posts to `/v1/messages?beta=true`; the `beta` flag is dropped
  before dispatch, so it never reaches a provider or a free pool.
- It aborts a stream after 300 seconds without bytes. Provider keep-alives are
  forwarded and the Worker adds `: multillm-keepalive` comments on idle streams.
- It prepends an attribution block to the system prompt. Translation joins the
  system blocks, so the block reaches translated models; set
  `CLAUDE_CODE_ATTRIBUTION_HEADER=0` to omit it.
- It sends `thinking: {"type": "adaptive"}` and, with experimental betas,
  `context_management`. Translated routes drop both safely. A native Messages
  model that rejects them makes Claude Code retry without thinking; set
  `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` if `context_management` is
  rejected.
- `GET /v1/models` accepts `x-api-key`, so
  `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1` works, but Claude Code lists
  only IDs containing `claude` or `anthropic`. Set other models with
  `ANTHROPIC_MODEL` or `/model <id>`.
- Native Messages errors pass through unmodified, which Claude Code's retry
  logic relies on; translated errors keep the upstream message and status.

### Anthropic SDK

```python
import anthropic

client = anthropic.Anthropic(base_url=PROXY_BASE_URL, api_key=MULTILLM_API_KEY)
message = client.messages.create(
    model="opencode:kimi-k3",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

```typescript
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ baseURL: process.env.PROXY_BASE_URL, apiKey: process.env.MULTILLM_API_KEY });
const stream = client.messages.stream({
  model: "auto:glm-5.2",
  max_tokens: 1024,
  messages: [{ role: "user", content: "Hello" }],
});
```

The Worker forwards `/v1/messages` and `/v1/messages/count_tokens` to the
Container like other `/v1` routes. The LinkAPI fast path handles only
`/linkapi/...`, so `/linkapi/v1/messages` stays a raw LinkAPI passthrough.

### OpenAI Responses clients

```bash
curl "$PROXY_BASE_URL/v1/responses" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "auto:glm-5.2", "input": "Hello", "stream": true}'
```

Send the whole conversation in `input` each turn; translated routes keep no
response state.
