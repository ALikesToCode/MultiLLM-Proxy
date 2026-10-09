# Local inference providers

Configure an OpenAI-compatible server explicitly to use `ollama`, `vllm`,
`lmstudio`, `llamacpp`, or `sglang` model prefixes. All five providers are
disabled when their base URL variables are unset or empty. There is no port
scanning, host discovery, model download, or inference runtime installation.

| Provider | Base URL variable | Optional provider key variable |
| --- | --- | --- |
| `ollama` | `OLLAMA_BASE_URL` | `OLLAMA_API_KEY` |
| `vllm` | `VLLM_BASE_URL` | `VLLM_API_KEY` |
| `lmstudio` | `LM_STUDIO_BASE_URL` | `LM_STUDIO_API_KEY` |
| `llamacpp` | `LLAMA_CPP_BASE_URL` | `LLAMA_CPP_API_KEY` |
| `sglang` | `SGLANG_BASE_URL` | `SGLANG_API_KEY` |

For example, set `OLLAMA_BASE_URL=http://127.0.0.1:11434/v1` before starting
standalone Flask. A bare origin receives `/v1`; a trailing slash is removed.
A service prefix such as `https://inference.example/serve/v1` is preserved.
Configure the server's actual OpenAI-compatible endpoint; Ollama's native
`/api/chat` protocol is not supported here.

URL validation rejects embedded credentials, query strings, fragments,
encoded paths, path traversal, invalid ports, and paths outside `/v1`.
Malformed settings disable that provider and log the variable name once without
its value. Plain HTTP accepts only explicitly configured loopback, RFC 1918,
or IPv6 unique-local addresses, and `localhost` names. Public HTTP, wildcard
bind addresses, multicast, and link-local metadata addresses are rejected.
Private DNS names require HTTPS; validation does not resolve DNS names.

Use a model already loaded on your server:

```json
{
  "model": "ollama:example-model:latest",
  "messages": [{"role": "user", "content": "Hello"}]
}
```

Send this body to `/v1/chat/completions` with your gateway authorization.
Only the provider prefix is removed from the upstream model ID. Requests go to
the configured `/v1/chat/completions`. Managed `/v1/responses` uses the existing
Chat conversion; native Responses continuation controls such as
`previous_response_id` return a real validation error before dispatch.
Gateway authorization remains required even when the local server needs no key.
Provider keys use the private provider credential loader and are sent only to
the configured upstream, never copied from the caller's gateway authorization.

A provider key is optional. When none is configured, an explicitly configured
local server is called without an `Authorization` header, both for generation
and for catalog refresh. Providers other than these five still refuse a request
when their key is missing.

Catalog refresh queries only configured servers at `/v1/models` using existing
refresh controls and transport timeouts. Results appear in `/v1/models` with
provider prefixes. Explicit model IDs do not require catalog discovery.
Failed refreshes retain the last good catalog and report the real failure;
disabled local providers' saved catalog entries are hidden.
Catalogs retain bounded provider declarations and attach
`provider_catalog:<provider>` provenance. Tools, vision, and other optional
capabilities are not inferred from model names or assumed from OpenAI API
compatibility. The adapter declares Chat and streaming transport support only.
The existing precision policy exposes declared precision when
`MODEL_PRECISION_PREFERENCE` is enabled; missing precision stays `unknown`.
Compatibility does not certify a server's model capabilities.

Local inference behind the Worker runs through Flask in its Container. Loopback
there means the Container, not the operator's workstation. Use a configured
origin reachable from the Container and follow the existing outbound/SSRF
policy; configuring a URL does not create connectivity or bypass that policy.
There is no GPU inference on the Worker and no additional native Worker route.

No monetary price is inferred for local compute. Existing accounting and
retention policies still apply; requests are not free merely because a server
is local. This integration stores model catalog metadata without provider
credentials and adds no prompt or response logging. Upstream errors remain
errors, and ambiguous generation failures do not authorize a new retry.
