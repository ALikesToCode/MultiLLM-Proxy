# Messages token counting

`POST /v1/messages/count_tokens` returns `{"input_tokens":123}`. Authenticate
with the gateway key through `x-api-key` or Bearer authorization. Key scope,
IP, expiry and requested-model restrictions apply before native dispatch.
The original provider-qualified model is authorized before its prefix is removed.

Use `X-MultiLLM-Token-Count-Mode` to select counting behavior:

- `estimate` (default): use the existing local estimator and return
  `X-MultiLLM-Token-Count: estimate`.
- `auto`: use a configured native count when available and return
  `X-MultiLLM-Token-Count: provider`. Unsupported or unconfigured capability
  uses the estimator with `X-MultiLLM-Token-Count-Fallback: unsupported`.
- `native`: require configured native counting. Unsupported capability returns
  HTTP 501 with an Anthropic error envelope identifying unsupported native counting.

Other header values return HTTP 400. Estimates retain the existing text, system,
tools and multimodal translation heuristic; they are not a provider tokenizer result.
Only explicit `provider:model` identifiers are eligible for native counts.
Bare names and automatic aliases use estimates in `auto` and return 501 in `native`.
Missing endpoint configuration or provider credentials is unconfigured capability.

## Endpoint configuration

`NATIVE_TOKEN_COUNT_ENDPOINTS_JSON` defaults to `{}`. Operators must verify
the provider's count endpoint before adding a registered provider ID and exact path:

```json
{"provider-id":"/v1/messages/count_tokens"}
```

This illustrates the shape, not a supported provider ID or verified reseller.
No provider is assumed to support counting merely because Messages generation works.
Paths must start with one slash and end with `/messages/count_tokens`.
Schemes, double slashes, dot segments, percent escapes, backslashes, query strings,
fragments and whitespace are rejected. Path segments use letters, digits, `_`,
`~`, `.`, and `-`. Invalid JSON, unregistered providers or invalid paths fail with
HTTP 500 in native dispatch modes and make no upstream call.

The trusted provider base URL supplies only the scheme and authority. Its path
is replaced with the configured count path, so `/v1` is never duplicated.
Include any required `/api`, `/coding` or other prefix explicitly in configuration.
For example, a base `https://provider.example/coding/v1` with a count path
`/coding/v1/messages/count_tokens` uses that exact origin and path.

## Native request and failures

The adapter sends one count-only POST with the provider-local model and the
allowlisted fields `messages`, `system`, `tools`, `tool_choice` and `thinking`.
Their contents, including multimodal blocks, are retained. Unknown top-level
fields and generation fields such as `max_tokens`, `stream` and `temperature`
are omitted. Configured credentials use the existing provider header builder;
caller credentials and proxy authentication headers are not forwarded.

The request has redirects disabled, zero automatic retries, cookie suppression
and connect/read timeouts of 5/10 seconds. Read timeout is not a total wall-clock
deadline. A response is bounded to 64 KiB and closed once after success or failure.
`input_tokens` must be a nonnegative JSON integer; zero is valid. Booleans,
strings, floats, negative or missing counts, nonfinite JSON, invalid JSON and
oversized responses return HTTP 502. Redirects and transport failures return
502; timeouts return 504. Upstream HTTP errors, including 401, 403, 404, 429
and 5xx, retain their status in an Anthropic error envelope with a sanitized
message. Neither `auto` nor `native` hides these errors behind estimates.

There is no generation call, provider failover, count cache, price charge,
token reservation or storage migration.

## Deployment

Standalone Flask reads the environment variable directly. The Worker forwards
this route to Flask in its Container, so there is no second count implementation;
`worker/container-env.mjs` forwards `NATIVE_TOKEN_COUNT_ENDPOINTS_JSON` to the Container.
