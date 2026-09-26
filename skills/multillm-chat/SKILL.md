---
name: multillm-chat
description: Call chat models through MultiLLM-Proxy from code or the command line, with OpenAI-compatible Chat Completions, Responses, the Anthropic-compatible Messages API, model discovery, automatic fallback routes and free model pools. Use when writing application code that needs an LLM, or when a task needs a completion through the user's MultiLLM gateway.
---

# MultiLLM Chat

MultiLLM-Proxy is an OpenAI-compatible gateway: one proxy key reaches many providers,
provider keys stay on the server, and automatic routes fall back between providers.
Point any OpenAI SDK at it.

- SDK base URL: `$MULTILLM_BASE_URL/v1`. A raw HTTP call uses the full path, for
  example `$MULTILLM_BASE_URL/v1/chat/completions`; never append `/v1` twice.
- Credential: `MULTILLM_API_KEY`, a MultiLLM proxy key (not a provider key) with the
  `chat` scope, plus `models` for discovery. Read it from the environment or the
  application's secret store. Never print it, commit it, log it, put it in a URL, or
  ship it to browser or mobile code; call the gateway from a server.

## Pick a model

List what this gateway serves before choosing; do not invent model IDs.

```bash
curl -sS "$MULTILLM_BASE_URL/v1/models" -H "Authorization: Bearer $MULTILLM_API_KEY"
```

Each `data[].id` is one of:

| Form | Meaning |
| --- | --- |
| `provider:model`, for example `nanogpt:zai-org/glm-5.2:thinking` | One provider and model, no fallback |
| `auto:<name>`, for example `auto:glm-5.2` | An operator-ordered list of candidates; the next runs after a definite refusal (auth, payment, missing model, rate limit, an open circuit) or a `500`, `502` or `503` before any output, never after a timeout or once output has started |
| `free:text`, `free:vision` | Free-tier pools that move to another free provider after quota exhaustion; never a paid model |
| `auto:intelligence` | Task-aware routing with a `routing` object, when an operator has enabled it |

`capabilities` shows `supports_chat`, `supports_images` and `supports_video`; offer only
models with `supports_chat: true` for chat (image, video, speech and embedding models are
`false`; Responses- and Messages-only models are translated, so they chat too). `context_window`, `max_output_tokens`, `supports_tools`, `supports_vision` and
list prices (`input_cost_per_million`, `output_cost_per_million` in USD) appear only when
the provider's catalog or models.dev publishes them; `metadata_provenance` names the source
of each filled value. Missing or `null` means unknown, not unsupported. Use a model's exact
ID, keep the `provider:` prefix, and prefer an `auto:` route when the user wants resilience
across providers.

## Chat Completions

Python (OpenAI SDK):

```python
import os
from openai import OpenAI

client = OpenAI(base_url=os.environ["MULTILLM_BASE_URL"] + "/v1",
                api_key=os.environ["MULTILLM_API_KEY"],
                max_retries=0)  # a retried generation can be billed twice

reply = client.chat.completions.create(
    model="auto:glm-5.2",
    messages=[{"role": "system", "content": "You are a concise assistant."},
              {"role": "user", "content": "Explain idempotency keys in two sentences."}],
    max_tokens=400,
)
print(reply.choices[0].message.content)

stream = client.chat.completions.create(model="auto:glm-5.2", stream=True,
                                        messages=[{"role": "user", "content": "Write a haiku about caches."}])
for chunk in stream:
    if chunk.choices and chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
```

TypeScript (OpenAI SDK):

```ts
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: `${process.env.MULTILLM_BASE_URL}/v1`,
  apiKey: process.env.MULTILLM_API_KEY,
  maxRetries: 0,
});

const reply = await client.chat.completions.create({
  model: "auto:glm-5.2",
  messages: [{ role: "user", content: "Summarize this diff in one line." }],
});
console.log(reply.choices[0].message.content);
```

curl, streaming:

```bash
curl -sS -N "$MULTILLM_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" -H "Content-Type: application/json" \
  -d '{"model": "free:text", "stream": true,
       "messages": [{"role": "user", "content": "Say hello in French."}]}'
```

Tools, `response_format`, images in `messages` and reasoning settings pass through to
the selected model; check `capabilities` first. `free:vision` accepts image input;
`/v1/free/text` and `/v1/free/vision` are fixed-purpose bases for the free pools.

## Tool calling on free pools

`free:text` and `free:vision` accept function `tools`, `tool_choice` and
`parallel_tool_calls`. The pool sends them only to free models with confirmed tool support
and answers `503 free_models_unavailable` when none is configured; it never switches to a
paid model. Only `{"type": "function"}` tools are accepted (at most 128, 64 KiB in total),
not server-side tools such as web search. The gateway never runs tools: read
`message.tool_calls`, run them yourself, and send the results back.

```python
tools = [{"type": "function", "function": {
    "name": "get_weather", "description": "Current weather for a city.",
    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}}]
messages = [{"role": "user", "content": "What is the weather in Paris?"}]
reply = client.chat.completions.create(model="free:text", messages=messages, tools=tools)
message = reply.choices[0].message
calls = [{"id": call.id, "type": "function",
          "function": {"name": call.function.name, "arguments": call.function.arguments}}
         for call in message.tool_calls or []]
messages.append({"role": "assistant", "content": message.content, "tool_calls": calls})
messages += [{"role": "tool", "tool_call_id": call["id"], "content": "18 C and sunny"} for call in calls]
final = client.chat.completions.create(model="free:text", messages=messages, tools=tools)
```

Send earlier turns back with only these fields (`role`, `content`, `tool_calls` with `id`,
`type` and `function`; `tool_call_id` on results): free pools reject extra message fields
such as `reasoning_content`.

A complete answer is checked before it is returned: calls must name a declared function
with JSON-object arguments and match `tool_choice`, otherwise the next free model runs.
Streamed tool calls are passed through unchecked.

## Other endpoints

- `POST /v1/responses`: the OpenAI Responses API for any chat model, including `auto:*`,
  `free:*` and `auto:intelligence`. Stateful features (`previous_response_id`,
  `conversation`, `background`) and built-in tools such as web search return `400`.
- `POST /v1/messages`: the Anthropic Messages API for any chat model, with the same
  routes and failover. It accepts `x-api-key` as well as `Authorization: Bearer`;
  `POST /v1/messages/count_tokens` gives a local estimate. Messages-compatible SDKs and
  agents work with their base URL set to `$MULTILLM_BASE_URL` (no `/v1`) and a
  MultiLLM model ID such as `auto:glm-5.2`.
- `POST /optimize/v1/chat/completions`: the same Chat Completions body for long
  conversations; the gateway compacts older history and reports what it did in
  `X-MultiLLM-Optimization*` headers.
- `POST /v1/images/generations`, `/v1/images/edits`, `/v1/images/batch`,
  `/v1/images/batches`, `/v1/videos`, `/v1/embeddings` and `/v1/audio/*`: media, embeddings
  and audio; see the `multillm-media` skill.
- `GET /v1/usage`: the key's own spend, remaining budget and recent history, for checking
  cost before a large job.
- `GET /status.json` (no key): current health of each automatic route and provider.
- Provider-native paths such as `/nanogpt/v1/...` exist for special cases. They have
  their own model IDs and permissions; do not switch to them unless asked.

## Read the response headers

`X-MultiLLM-Provider`, `X-MultiLLM-Model` and `X-MultiLLM-Route-Decision` say who
answered; automatic routes add `X-MultiLLM-Auto-Selected-Model` and
`X-MultiLLM-Auto-Attempts`, and `X-MultiLLM-Auto-Failover-Reasons` lists the candidates
passed over and why. `X-MultiLLM-Latency-Ms`, `X-MultiLLM-Estimated-Cost-USD` and
`X-MultiLLM-Circuit-State` help with monitoring. Log the selected model, never the key.

## Cache repeated deterministic calls

Send `X-MultiLLM-Cache: on` with a non-streaming request that has `temperature: 0` or an
integer `seed` and no tools. An identical request from the same key within the cache
lifetime is answered from the cache without calling a provider or charging the budget;
the response says `X-MultiLLM-Cache: hit`, `miss` or `bypass`. `Cache-Control: no-cache`
forces a fresh answer.

## Errors and retries

- `401`: the key is missing or invalid, or `key_expired`. `403`: the key lacks the scope
  (`chat`, `models`), or `model_not_allowed` (the key's allowlist excludes that model) or
  `ip_not_allowed`. Ask the user to fix the key or pick an allowed model; do not try other
  endpoints to get around it.
- `429 budget_exceeded`: the key's daily or monthly dollar budget is spent; `Retry-After`
  points to the reset. Stop and tell the user; `GET /v1/usage` shows the budget.
- `400`: the request does not fit the model (unknown model, unsupported field or
  size). Fix the request.
- `429`: a rate limit or allowance; wait for `Retry-After` when present, then retry
  once.
- `5xx` or a timeout: the provider may already have done billable work. Do not retry
  automatically in a loop; surface the error, and retry once only when the user or the
  application's policy accepts the cost. Automatic routes already try their other
  candidates after definite refusals and after a `500`, `502` or `503` with no output.
- Streams can end early: treat a stream without a final `finish_reason` as incomplete.

## From an agent, without code

Coding agents can use the same gateway as MCP tools at `$MULTILLM_BASE_URL/v1/mcp`:
`list_models`, `chat` (defaults to `free:text`), `generate_image`, `generate_images_batch`,
`create_video`, `get_video` and `media_providers`. See the `multillm-mcp` skill for client
setup and rules.

## When writing application code

- Put `MULTILLM_BASE_URL` and `MULTILLM_API_KEY` in configuration, not in code; add
  them to `.env.example` without values.
- Set SDK retries to 0 and add timeouts sized for long generations (120 s or more).
- Keep the model ID configurable, defaulting to an `auto:` route or a discovered
  `provider:model`.
- Verify with `GET /v1/models` first, then one small request within the user's
  authorized scope, and report the endpoint and model used.
