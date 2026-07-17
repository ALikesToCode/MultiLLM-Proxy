# Opt-in context optimizer design

## Goal

Add an explicit OpenAI-compatible chat route that can reduce stale context before
dispatching to any configured unified provider, without changing the behavior of
the existing raw or unified proxy routes.

The route is:

```text
POST /optimize/v1/chat/completions
```

It accepts the normal unified `provider:model` chat payload plus a proxy-only
`optimization` object. The proxy removes `optimization` before the upstream
request.

## Why the route is opt-in

Context editing can change model behavior. Applying it to every request would
break the proxy's byte-preserving contract and could invalidate provider prompt
caches. Existing routes therefore remain unchanged:

- `/v1/chat/completions` remains the normal unified route.
- `/<provider>/...` remains the provider-native route.
- `/optimize/v1/chat/completions` is the only route that edits history.

The optimized route remains Container-backed. Provider-specific direct Worker
paths continue to handle raw traffic, while the optimized route uses the shared
model resolution, authentication, rate limiting, and dispatch code.

## Request contract

```json
{
  "model": "kimi-code:k3",
  "messages": [],
  "stream": true,
  "prompt_cache_key": "session-123",
  "optimization": {
    "mode": "deterministic",
    "target_input_tokens": 96000,
    "trigger_input_tokens": 96000,
    "keep_recent_turns": 8,
    "image_prompt_history": "latest",
    "media_history": "all",
    "preserve_message_indices": [],
    "require_target": false
  }
}
```

Defaults derive the trigger and target from 75% of the configured provider
prompt limit. Counts are explicitly estimates because providers tokenize
differently.

Supported modes:

- `deterministic`: no extra model call; only high-confidence safe rewrites.
- `summarize`: deterministic compaction followed, if still needed, by one
  caller-selected summary-model request over eligible old ordinary text turns.

`summarize` requires `summary_model`. It is explicitly paid because it adds
latency, another provider request, and possible cross-provider data transfer.
The first release constrains summary models to native/raw OpenAI-compatible
providers so the summary request has one-attempt transport semantics.

## Deterministic compaction

The optimizer always preserves:

- all system and developer messages in place;
- the configured number of recent user turns through the end of history;
- the latest user turn and everything after it;
- the newest detected image-generation prompt;
- tool/function call chains and IDs;
- `reasoning_content`, thinking blocks, signatures, and unknown reasoning fields;
- real image, audio, file, and other non-text content blocks;
- top-level tools, response schemas, provider-specific options, and
  `prompt_cache_key`.

An image-generation prompt is eligible only when all high-confidence checks
match: it is long, contains a create/generate-image directive, and contains at
least three labelled visual sections such as background, character, outfit,
lighting, or composition. Older eligible prompts are replaced with one stable
placeholder:

```text
[Earlier image-generation prompt omitted by MultiLLM context optimizer; the newest prompt is retained.]
```

The placeholder has no timestamp, hash, or token count, keeping rewritten
prefixes stable. If recent turns explicitly refer to an earlier image or prompt,
automatic image-prompt compaction is skipped.

Actual historic media remains untouched. `media_history` accepts only `all` in
this release.

## Summary mode

Summary mode sends only eligible old ordinary user/assistant text to the chosen
summary model. It never sends system/developer messages, tools, tool results,
media, current tool loops, reasoning content, or signed thinking blocks.

The summary prompt treats the history as untrusted data and requests validated
JSON fields:

- facts;
- requirements;
- decisions;
- open tasks;
- visual continuity.

The proxy validates and bounds every returned string, then inserts the digest as
an explicitly untrusted historical-memory user message. Invalid output, an
upstream failure, or a denied summary budget causes a deterministic fallback
without retry. The final provider request still proceeds unless
`require_target` is true and the safe result cannot reach the requested target.

## Authentication and accounting

The existing API decorator authenticates and reserves rate-limit usage before a
route runs. The optimized route instead uses a shared authenticate-only
decorator, checks the original body-size limit, performs optimization, then
reserves rate and token budgets against the transformed request exactly once.
Summary mode reserves its separate model call separately.

This prevents a long but safely compactable prompt from being rejected or
counted against the pre-compaction estimate.

## Response contract

The upstream JSON or SSE body remains unchanged. Optimization information is
reported only in response headers:

```text
X-MultiLLM-Optimization: applied
X-MultiLLM-Optimization-Mode: deterministic
X-MultiLLM-Estimated-Input-Before: 118400
X-MultiLLM-Estimated-Input-After: 74200
X-MultiLLM-Image-Prompts-Compacted: 4
X-MultiLLM-Messages-Summarized: 0
```

Malformed options return `400`. Unknown content is preserved. Missing a target
is informational unless `require_target` is true.

## Cost and cache behavior

Deterministic mode adds no provider call. It favors a stable replacement string
and preserves `prompt_cache_key`, but any edit to old history can still
invalidate a cache prefix. Compaction only triggers near the configured context
threshold by default so the token saving is large enough to justify that cache
tradeoff.

Summary mode is never automatic. It may reduce substantially more tokens, but
it explicitly trades an extra paid request and cache-prefix rewrite for a
smaller final context.
