# Omni on the intelligence gateway

What Omni needs to keep calling `auto:intelligence`, as deployed on 2026-10-05. The full
contract is in [the intelligence gateway reference](intelligence-gateway.md); the dated
pilot record is [the Omni subscription pilot](intelligence-omni-pilot.md).

## Endpoint and key

- `POST https://multillm-proxy.cserules.workers.dev/v1/chat/completions` with
  `model: "auto:intelligence"`. `POST /intelligence/v1/chat/completions` is the same
  route and defaults an omitted model to `auto:intelligence`.
- `Authorization: Bearer <Omni's integration key>`. The key belongs to principal
  `integration:omni` and needs the `chat` and `models` scopes. Keep it in Omni's
  secret store; never put it in prompts, URLs or logs.
- Optional `X-Request-ID` (up to 128 safe characters) is echoed in the response header
  and in `multillm.request_id`. Do not send `Idempotency-Key`: it is refused with
  `idempotency_not_supported`.

## Request

```json
{
  "model": "auto:intelligence",
  "messages": [
    {"role": "system", "content": "You are Omni, a personal assistant."},
    {"role": "user", "content": "What needs me today?"}
  ],
  "tools": [{"type": "function", "function": {"name": "get_tasks", "parameters": {"type": "object"}}}],
  "max_tokens": 2048,
  "reasoning_effort": "medium",
  "stream": true,
  "routing": {
    "version": 1,
    "source": "jev",
    "profile": "balanced",
    "task": "general",
    "max_total_tokens": 24000
  }
}
```

Allowed top-level fields: `model`, `messages`, `tools`, `tool_choice`,
`parallel_tool_calls`, `response_format`, `reasoning_effort`, `max_tokens`,
`max_completion_tokens`, `stream`, `stream_options` (only `include_usage`),
`temperature`, `top_p`, `stop`, `seed`, `frequency_penalty`, `presence_penalty`,
`logit_bias`, `logprobs`, `top_logprobs`, `n` (must be 1), `user`, `modalities`,
`audio`, `routing`. Any other field fails the whole request, including `instructions`,
`metadata`, `store` and provider billing fields.

- **Messages:** roles `system`, `developer`, `user`, `assistant`, `tool`; at most 1,024
  messages. Content is a string or a list of `text` parts. A `tool` message needs
  `tool_call_id`.
- **Tools:** function tools only, at most 128, unique names matching
  `[A-Za-z0-9_-]{1,64}`, parameters as JSON Schema with local `$ref`s only.
- **Output:** `max_tokens` is capped at 4,096 per reply.
- **Reasoning effort:** `none`, `minimal`, `low`, `medium`, `high`, `xhigh` or `max`.
  The gateway translates for each model family: GLM turns `xhigh` into `max`; MiMo uses
  only `none` (for `none` and `minimal`) or `high`; Gemini 3.8 Flash uses `low` for
  `none` and `minimal`, and `high` for `xhigh` and `max`. GPT-6.1 Sol uses `low` for
  `minimal`, because Codex Everywhere's Pro pool refuses `minimal` for it. GPT-6 Luna and
  Grok 4.7 accept every value, `minimal` and `max` included (tested 2026-10-05).
- **System prompt:** send it as a normal `system` message. For the GPT models the
  gateway moves it into Codex's `instructions`, so they answer as Omni rather than as a
  coding agent.

### Routing hints

| Field | Values | Effect today |
|---|---|---|
| `version` | `1` | Required to be 1 when present |
| `profile` | `balanced` (default), `quality`, `fast` | Picks the order; see below |
| `source` | `jev`, `rules` (default), `explicit` | Recorded |
| `task` | `general` (default), `coding`, `reasoning`, `planning`, `assessment`, `research`, `writing` | No effect yet: no model has task scores |
| `required_capabilities` | `tools`, `json`, `vision`, `reasoning`, `streaming`, `audio` | Skips models without them. Tools, JSON output, reasoning and streaming are also inferred from the request |
| `max_total_tokens` | Up to 131,072 | Token bound for the whole request, all attempts included |
| `max_attempts` | Up to 16 | Submissions per request |
| `max_escalations` | 0 or 1 | Retries on a stronger model after invalid JSON or tool output |
| `deadline_ms` | Up to 45,000 | One deadline for every attempt and the whole reply |
| `allow_paid_overage` | `false` | `true` changes nothing: the server forbids paid usage |

Each limit is clamped to the server ceiling shown.

## Which models answer

| Profile | Use it for | First choice, then |
|---|---|---|
| `balanced` | Normal turns | GLM 5.3 Flash (NanoGPT, then Cline Pass), GPT-6 Luna (Plus, Pro), GPT-6.1 Sol, MiMo on Cline Pass, Grok 4.7, Gemini 3.8 Flash, GLM 5.3, GLM 5.2, Gemini 3.5 Flash-Lite, MiMo on NanoGPT |
| `quality` | Hand-offs and turns that need thought | Highest tier first: GPT-6.1 Sol (Pro, then Plus), MiMo on Cline Pass and Grok 4.7, Gemini 3.8 Flash and GLM 5.3, then the rest |
| `fast` | Latency-critical turns | Fastest measured reply among healthy models |

Measured on 2026-10-05: a balanced turn picked NanoGPT GLM 5.3 Flash; quality picked
GPT-6.1 Sol on Codex Everywhere Pro in 7.9 s; GPT-6 Luna on Plus answered in 2.5 s.

Omni can pin one model by sending its ID as `model` with a `routing` object, for example
`"source": "explicit"`. A pinned model is never replaced by another; it only retries on a
spare key. These IDs are enabled:

```
nanogpt:z-ai/glm-5.3-flash          cline-pass:cline-pass/glm-5.3-flash
ce-gpt-plus:gpt-6-luna              ce-gpt-pro:gpt-6-luna
ce-gpt-plus:gpt-6.1-sol             ce-gpt-pro:gpt-6.1-sol
cline-pass:cline-pass/mimo-v2.6-pro ce-grok-heavy:grok-4.7
gemini:gemini-3.8-flash             nanogpt:z-ai/glm-5.3
cline-pass:cline-pass/glm-5.3       aihubmix:coding-glm-5.3-free (no tools)
nanogpt:z-ai/glm-5.2                aihubmix:coding-glm-5.2-free (no tools)
gemini:gemini-3.5-flash-lite        nanogpt:xiaomi/mimo-v2.6-pro (59-152 s, last resort)
```

The operator changes this chain in the gateway; Omni needs no change when models are
added or reordered.

## Photos

No model in the live policy accepts images yet, so a request with an image fails with
`no_eligible_model`. Gemini 3.8 Flash and Gemini 3.5 Flash-Lite read `image_url` parts
with `data:image/png;base64,...` or JPEG URLs (tested 2026-10-05, about 1,100 prompt
tokens per photo); giving them `vision` and a `media_input_tokens` ceiling in the policy
turns photos on. A request with an image then goes only to models with vision, whatever
the profile, and reserves the model's media ceiling on top of its text, so allow for
that in `max_total_tokens`. The encoded photo itself is not counted as text. The whole
request body must stay under 1 MiB, so resize photos before encoding them. Audio input
is not available.

## Tool calls with Gemini

Gemini 3.8 Flash signs each tool call in `extra_content.google.thought_signature` and
refuses the follow-up unless that field comes back. When Omni replays an assistant
message with `tool_calls`, keep each call's `extra_content` exactly as received. The
gateway removes it for other providers.

## Response

The selected model is in `model` and `multillm.selected_model`. `multillm` also has
`version`, `request_id`, `selected_provider`, `attempts`, `escalations`, `reason`
(`policy`, `explicit`, `availability_fallback` or `quality_escalation`) and
`usage_complete`. `usage` sums every attempt; it is `null` when unknown. The gateway's
usage ledger records the same model in `usage_events.selected_model`.

Streaming is Chat Completions SSE with indexed tool-call deltas. The final event carries
`usage` and `multillm` before `[DONE]`. Treat a turn as finished only when that final
event arrived: an interrupted stream sends an error event and then `[DONE]`. JSON and
tool replies are held back until they validate, so they arrive late and all at once.

## Errors

Errors are `{"error": {"code", "message", "retryable"}}`, with `Retry-After` when
known. Retry only when `retryable` is true, and wait as long as `Retry-After` says.

| Code | HTTP | Meaning | Omni should |
|---|---|---|---|
| `invalid_routing_request` | 400 | A field or value is not allowed | Fix the request |
| `request_too_large` | 413 | The request body is over 1 MiB | Shorten the history |
| `token_budget_exhausted` | 429 | `max_total_tokens` has no room left for another attempt | Raise the bound or shorten the history |
| `allowance_exhausted` | 429 | Daily tokens used up, or 2 requests already running | Wait for `Retry-After` (60 s) |
| `gateway_busy` | 503 | Every transport slot in use | Retry shortly |
| `no_eligible_model` | 503 | No model fits the request (for example images or audio) | Change the request |
| `output_validation_failed` | 502 | JSON or tool output stayed invalid after escalation | Retry or simplify the schema |
| `deadline_exceeded` | 504 | 45 s passed | Retry with a smaller job or the `fast` profile |
| `upstream_error`, `upstream_interrupted`, `stream_interrupted` | 502 | The provider failed or stopped mid-reply | Retry the turn as new |

## Budget

- Omni's principal and the gateway as a whole each get 1,048,576 tokens per rolling
  24 hours. The global cap is shared with every other intelligence caller.
- At most 2 requests run at once, counted across every intelligence caller, not just Omni.
- Each request reserves its `max_total_tokens` (131,072 when omitted) until it settles.
  Send a realistic bound, about the history size plus `max_tokens`, with room for one
  fallback. A missing bound makes every turn reserve 131,072 tokens.
- With `usage_complete: false` the reservation stays charged, and so does an outcome
  the gateway could not confirm, such as a reply cut off at the deadline. Those stay
  charged past the 24 hours until an operator settles them, so keep turns well inside
  45 s.

## Health

`GET /v1/models` with Omni's key lists `auto:intelligence` with
`availability: "unverified"`; it does not probe providers. A small balanced request is
the real check.
