# Roleplay endpoint client guide

How to call the roleplay endpoints as deployed on 2026-10-05. The full behaviour is in
[the roleplay reference](roleplay.md); NanoGPT details are in [NanoGPT](nanogpt.md).

## Endpoints and key

| Route | Use it for |
|---|---|
| `POST /roleplay/v1/chat/completions` | JanitorAI and other OpenAI-compatible chat clients |
| `POST /v1/roleplay/chat/completions` | The same route under `/v1` |
| `POST /v1/roleplay` | The native body with `session_id`, `character`, `lore` and `memory` |
| `GET /v1/roleplay/models` | The configured models and their limits |
| `GET /v1/roleplay/metrics?session_id=...` | One session's routing statistics, without its dialogue |

The base URL is `https://multillm-proxy.cserules.workers.dev`. Send
`Authorization: Bearer <ROLEPLAY_API_KEY>`. The administrator key also works; the
general gateway key and Omni's integration key get `401 unauthorized`. Keep the key in
the client's key field, never in a prompt or URL.

## JanitorAI

| Field | Value |
|---|---|
| Proxy URL | `https://multillm-proxy.cserules.workers.dev/roleplay/v1/chat/completions` |
| API key | `ROLEPLAY_API_KEY` |
| Model | `roleplay:auto` |
| Custom prompt | None, unless the character needs an extra instruction |

The proxy URL is already the full endpoint, so leave **Add `/chat/completions`**
disabled. Save the configuration and hard-refresh JanitorAI before selecting it. If the
Worker logs show `POST /v1/chat/completions`, JanitorAI is bypassing the roleplay route:
re-enter the URL above. That route has none of the roleplay memory, continuation or
refusal handling.

Requests from `https://janitorai.com` always get unlimited output, whatever the
**Max tokens** setting says.

JanitorAI sends no conversation ID, so the Worker picks the session from the key and
the opening of the chat: the messages up to and including the first user message. Two
chats with the same character, greeting and first message therefore share one session
and its memory. Start one of them with a different first message to keep them apart.

## Request

An OpenAI-compatible turn:

```json
{
  "model": "roleplay:auto",
  "messages": [
    {"role": "system", "content": "You are Mira, a guarded court mage."},
    {"role": "user", "content": "I close the library door and ask who followed us."}
  ],
  "stream": true
}
```

The native route takes `session_id`, `input` (one new user turn) or `messages`,
`character` (`name`, `persona`, `scenario`, `style`), `lore` (entries with `keys` and
`content`), `model_preference`, `response_length`, `prompt_cache`, `memory`,
`history_mode`, `output_mode` and `stream`. See the example in
[the roleplay reference](roleplay.md#request).

- **Session:** `session_id` or the `X-Roleplay-Session-ID` header, 8 to 128 letters,
  digits, `_` or `-`. Without one the Worker uses `conversation_id`, `chat_id` or
  `thread_id`, then the opening messages. A request that sends only the newest message
  and no ID starts a new session with no memory, so API clients should send one.
- **History:** `history_mode` is `auto` (default, detects full history or new messages
  only), `append` or `replace`. Sending the full history each turn is fine.
- **System messages:** `system` and `developer` messages are kept as protected
  instructions and reused on later turns that leave them out. They are never
  summarised; if they don't fit any model, the turn fails with `413`.
- **Reasoning:** leave `reasoning_effort` out. The default is `high`, and NanoGPT gets
  no effort at all, so it uses its own thinking mode. `max` becomes each provider's
  strongest level. `none` on NanoGPT GLM 5.3 fails with `400 reasoning_required`.
- **Duplicates:** an optional `Idempotency-Key` header stops a retried turn from
  running twice. Reusing a key returns `409 duplicate_roleplay_turn`; it does not
  replay the earlier reply.
- **Size:** the request body can be up to 8 MiB.

## Models

Set `model` (or `model_preference` on the native route). The plain IDs `kimi-k2.6`,
`glm-5.3-flash`, `glm-5.3`, `glm-5.2` and NanoGPT's `z-ai/...` and `zai-org/...` GLM IDs
pin the matching selector below. An unknown `roleplay:` selector fails with `400`; any
other `model` is treated as `roleplay:auto`.

| Selector | Tries, in order | Notes |
|---|---|---|
| `roleplay:auto` | ClinePass GLM 5.3; NanoGPT MiMo V2.6 Pro, GLM 5.3, GLM 5.3 Flash, GLM 5.2; ClinePass GLM 5.3 Flash, MiMo V2.6 Pro | Use this |
| `roleplay:intelligence` | The same list | |
| `roleplay:glm` | NanoGPT GLM 5.3 Flash, GLM 5.3 Flash Uncensored, GLM 5.2 (thinking); NavyAI GLM 5.2 Venice | Rewrites a Flash refusal |
| `roleplay:glm-speed` | The same models, fastest in this session first | |
| `roleplay:5.3-flash` | NanoGPT GLM 5.3 Flash only | |
| `roleplay:5.3-flash-uncensored` | NanoGPT GLM 5.3 Flash Uncensored only | Thinks at `high` at most |
| `roleplay:5.3` | NanoGPT GLM 5.3 only | Uses twice the subscription tokens |
| `roleplay:5.2` | NanoGPT GLM 5.2 (thinking); NavyAI GLM 5.2 Venice | |
| `roleplay:uncensored` | NanoGPT GLM 5.3 Flash Uncensored; NavyAI GLM 5.2 Venice | |
| `roleplay:speed` | NanoGPT GLM models; LinkAPI Kimi K2.6; NavyAI | Can reach LinkAPI, which bills per use |
| `roleplay:kimi` | LinkAPI Kimi K2.6 only | Pay-as-you-go; `503 no_roleplay_provider` without a LinkAPI key |

The `roleplay:auto` list is strict: a provider without a key is skipped, and a reply
of `400`, `401`, `402`, `403`, `404`, `413`, `415`, `422`, `429` or `503`, a failed
connection, or no response headers within 90 s moves to the next entry. A `500`, `502`
or `504` moves on only when the provider labels it `provider_error`; any other server
error stops the turn, because the provider may already have started writing.

Measured on 2026-10-05: ClinePass GLM 5.3 gave its first words in about 4 s. MiMo on
NanoGPT took 59 s, and 152 s on an adult turn, so a turn that falls back to it is slow.
NavyAI's free plan and OpenCode Go were refusing every request; NavyAI is still the
last fallback of the GLM selectors, so a turn that reaches it will fail.

If GLM 5.3 Flash refuses a scene, use `roleplay:glm`: it replaces a Flash refusal with
GLM 5.3 Flash Uncensored without showing or storing the refusal. `roleplay:auto` has no
Uncensored model in its list, so it does not.

## Output and streaming

- Streaming is on unless `"stream": false` is sent. Replies are Chat Completions JSON or
  SSE, passed through from the provider.
- Without `max_tokens` the Worker asks for the largest reply the model allows. A
  `max_tokens` value is a ceiling and is clamped to the model's limit.
  `output_mode: "unlimited"` or `max_tokens` of 1,000,000 or more removes the ceiling.
- In unlimited mode a reply cut off at the model's output limit, or by a dropped
  provider connection after some text, continues by itself up to 8 times and arrives
  as one reply with one `[DONE]`.
- During a quiet stretch the Worker sends an SSE comment (`: roleplay-keepalive`)
  every 10 s. There is no overall deadline; the stream runs until the model finishes.
  Set client
  read timeouts in minutes, not seconds.
- `response_length` is `compact`, `balanced` (default) or `immersive`. It changes
  pacing, not the token limit.

## Memory

The session keeps the exact dialogue until it passes 128,000 estimated tokens. Then
older turns are summarised and the newest 32 messages stay word for word. The summary
is written by the model answering the turn, or by Kimi K2.6 when that model is on
NanoGPT. If the summary fails, a local summary is used and `X-Roleplay-Memory` says
`local_compacted`. `memory: {"mode": "off"}` skips memory for one turn; `force`
summarises now. A session is deleted after 30 days without a turn.

## Which model answered

Response headers: `X-Roleplay-Provider`, `X-Roleplay-Model`,
`X-Roleplay-Fallback-Count` (attempts before this one, refusal rewrites included),
`X-Roleplay-Selection`, `X-Roleplay-Memory`, `X-Roleplay-Max-Output-Tokens`,
`X-Roleplay-Session-ID` and `Server-Timing`. Clients
that hide headers, such as JanitorAI, still see the route at the start of the thinking
block, `<think>[provider: nanogpt | model: z-ai/glm-5.3]`, when the model returns
reasoning.

`GET /v1/roleplay/models` lists only the models of the adaptive selectors, not the
`roleplay:auto` list, and its `model_aliases` text for `roleplay:intelligence` still
describes the built-in default (MiMo first) rather than the production list above.

## Errors

Errors are `{"error": {"code", "message", "type"}}`.

| Code | HTTP | Meaning | Do this |
|---|---|---|---|
| `unauthorized` | 401 | Wrong key | Use `ROLEPLAY_API_KEY` |
| `invalid_request` | 400 | A field or selector is not allowed | Fix the request |
| `duplicate_roleplay_turn` | 409 | The `Idempotency-Key` was already used | Send a new key for a new turn |
| `request_too_large` | 413 | Body over 8 MiB, or protected instructions too long for any model | Shorten them |
| `roleplay_context_too_large` | 413 | The context and requested output fit no model | Lower `max_tokens` or start a new session |
| `no_roleplay_provider` | 503 | No model with a key serves this selector | Use `roleplay:auto` |
| Provider's own code | Provider's | Every entry rejected the turn; the last provider's status, body and `Retry-After` are passed through | Wait for `Retry-After`, then retry |
