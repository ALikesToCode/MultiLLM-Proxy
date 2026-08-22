# OpenCode Go integration

MultiLLM Proxy exposes the OpenCode Go subscription API under `/opencode/*`.
The integration follows the live
[OpenCode Go documentation](https://opencode.ai/docs/go).

The canonical `/opencode/v1/*` routes preserve OpenAI and Anthropic request
bodies, status codes, repeated query parameters, and safe rate-limit/request
headers. OpenAI Chat Completions responses have one deliberate compatibility
layer: duplicate or malformed provider reasoning is reconciled into one visible
route-labelled `<think>` block. The proxy does not translate one protocol into
the other.

On Cloudflare, the Worker validates the proxy credential before waking the
Container, then the Container performs the upstream request. This is required
because OpenCode currently rejects Worker-origin HTTP signatures with
Cloudflare error `1010`. The split-auth headers and provider credential stay
inside the trusted Worker-to-Container request.

## Configuration

```env
OPENCODE_GO_API_KEY=your-opencode-go-api-key

# Compatibility alias
# OPENCODE_API_KEY=your-opencode-go-api-key

# Optional upstream override
# OPENCODE_GO_BASE_URL=https://opencode.ai/zen/go/v1
```

`OPENCODE_GO_API_KEY` takes precedence when both key names are set.

## Client base URLs

| Client | Proxy base URL |
| --- | --- |
| OpenAI-compatible SDK | `$PROXY_BASE_URL/opencode/v1` |
| Anthropic SDK | `$PROXY_BASE_URL/opencode` |
| Direct HTTP | `$PROXY_BASE_URL/opencode` plus `/v1/...` |

OpenAI-compatible example:

```python
from openai import OpenAI

client = OpenAI(
    api_key="YOUR_MULTILLM_PROXY_KEY",
    base_url="https://your-proxy.example/opencode/v1",
)

response = client.chat.completions.create(
    model="kimi-k3",
    messages=[{"role": "user", "content": "Review this function."}],
)
```

Anthropic-compatible example:

```python
import anthropic

client = anthropic.Anthropic(
    api_key="YOUR_MULTILLM_PROXY_KEY",
    base_url="https://your-proxy.example/opencode",
)

response = client.messages.create(
    model="minimax-m3",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Review this function."}],
)
```

The OpenAI client authenticates MultiLLM Proxy with `Authorization: Bearer`.
The Anthropic client can authenticate it with `X-Api-Key`. The proxy replaces
that credential with the configured OpenCode Go key and uses the native
upstream header for the selected protocol.

## Endpoints

| Capability | Direct OpenCode Go URL | Proxy URL |
| --- | --- | --- |
| OpenAI Chat Completions | `POST https://opencode.ai/zen/go/v1/chat/completions` | `POST /opencode/v1/chat/completions` |
| Anthropic Messages | `POST https://opencode.ai/zen/go/v1/messages` | `POST /opencode/v1/messages` |
| Model discovery | `GET https://opencode.ai/zen/go/v1/models` | `GET /opencode/v1/models` |

Use the model catalog at runtime because OpenCode may add or remove models as
it tests provider/model combinations.

## Current model and protocol mapping

| Model | Request model ID | Protocol |
| --- | --- | --- |
| Grok 4.5 | `grok-4.5` | OpenAI Chat Completions |
| Ox Alpha Free | `ox-alpha-free` | OpenAI Chat Completions |
| GLM-5.2 | `glm-5.2` | OpenAI Chat Completions |
| GLM-5.1 | `glm-5.1` | OpenAI Chat Completions |
| Kimi K3 | `kimi-k3` | OpenAI Chat Completions |
| Kimi K2.7 Code | `kimi-k2.7-code` | OpenAI Chat Completions |
| Kimi K2.6 | `kimi-k2.6` | OpenAI Chat Completions |
| MiMo-V2.5 | `mimo-v2.5` | OpenAI Chat Completions |
| MiMo-V2.5-Pro | `mimo-v2.5-pro` | OpenAI Chat Completions |
| DeepSeek V4 Pro | `deepseek-v4-pro` | OpenAI Chat Completions |
| DeepSeek V4 Flash | `deepseek-v4-flash` | OpenAI Chat Completions |
| Hy3 | `hy3` | OpenAI Chat Completions |
| MiniMax M3 | `minimax-m3` | Anthropic Messages |
| MiniMax M2.7 | `minimax-m2.7` | Anthropic Messages |
| MiniMax M2.5 | `minimax-m2.5` | Anthropic Messages |
| Qwen3.7 Max | `qwen3.7-max` | Anthropic Messages |
| Qwen3.7 Plus | `qwen3.7-plus` | Anthropic Messages |
| Qwen3.6 Plus | `qwen3.6-plus` | Anthropic Messages |

OpenCode configuration uses `opencode-go/<model-id>`, for example
`opencode-go/kimi-k3`. That prefix belongs to OpenCode's own configuration.
Direct API requests through this proxy send only `kimi-k3`. MultiLLM's unified
Chat route instead uses its normal `provider:model` form:

```json
{
  "model": "opencode:kimi-k3",
  "messages": [{"role": "user", "content": "Hello"}]
}
```

### Ox Alpha Free

The OpenCode Go catalog currently exposes Ox Alpha Free as
`ox-alpha-free`. This differs from the separate public Zen catalog, where the
corresponding preview may appear as `x-preview-f-free`. MultiLLM Proxy uses the
Go subscription base URL, so configure Janitor AI or another OpenAI-compatible
client with:

```json
{
  "model": "ox-alpha-free"
}
```

For the unified route, use `opencode:ox-alpha-free` instead.

## Streaming and compatibility

`POST /opencode/v1/chat/completions` preserves OpenAI SSE framing while
reconciling `reasoning_content`, `reasoning`, `reasoning_details`, and raw
`<think>` markup. When reasoning is present, clients receive exactly one block:

```text
<think>[provider: opencode | model: ox-alpha-free]
...reasoning...</think>

...visible response...
```

The response also exposes `X-MultiLLM-Provider` and `X-MultiLLM-Model`.
`POST /opencode/v1/messages` preserves Anthropic events such as
`message_start`, `content_block_delta`, `message_delta`, and `message_stop`.

The older `POST /opencode/chat/completions` route remains available for
backward compatibility. It retains MultiLLM Proxy's historical OpenAI stream
normalization, including visible reasoning blocks and recovery from a specific
legacy OpenCode timeout payload. New clients should use the canonical
`/opencode/v1/...` routes.

Native routes are single-attempt and do not follow upstream redirects or retain
upstream cookies. This prevents duplicate coding requests and credential
cross-contamination. Retry a failed request in the client only when doing so is
safe for that operation.

## Caller-owned OpenCode Go keys

To use a different OpenCode Go subscription for one request, authenticate
MultiLLM Proxy separately:

```bash
curl "$PROXY_BASE_URL/opencode/v1/chat/completions" \
  -H "X-MultiLLM-Api-Key: $ADMIN_API_KEY" \
  -H "Authorization: Bearer $CALLER_OPENCODE_GO_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k3","messages":[{"role":"user","content":"Hello"}]}'
```

For Anthropic Messages, combine `X-MultiLLM-Api-Key` with the caller's
`X-Api-Key`. Caller-owned credentials work even when the server has no
`OPENCODE_GO_API_KEY`.

## Subscription and upstream limits

OpenCode currently advertises Go at $5 for the first month and $10/month
afterward. The upstream subscription windows are:

| Window | Included usage value |
| --- | ---: |
| Five hours | $12 |
| Week | $30 |
| Month | $60 |

Actual request counts depend on the selected model, cached-token volume, and
input/output length. Some models currently have $15 rather than $60 of monthly
included model usage because their upstream discount multiplier is lower.
OpenCode documents the current estimates and token prices in its Go page.

These are upstream monetary limits, not MultiLLM request-rate limits. The proxy
does not duplicate or predict OpenCode's billing calculation. Track authoritative
usage in the OpenCode console. If the subscription reaches a limit, OpenCode
allows free models, and users with Zen credits can enable the console's
`Use balance` fallback.

Only one member per OpenCode workspace can subscribe to Go.

## Privacy and hosting

OpenCode describes Go as intended primarily for international users, with
models hosted in the United States, European Union, and Singapore. Its
documentation states that the serving providers follow a zero-retention policy
and do not use request data for model training. Evaluate that upstream policy
against your own data-handling requirements before sending sensitive code.
