# OpenAPI contract

`GET /openapi.json` returns the reviewed OpenAPI 3.1.0 client contract. Use an
existing dashboard session or a gateway bearer credential with `models` scope
(administrators also qualify). `X-MultiLLM-Api-Key` is an alternative gateway
credential. Anonymous browser requests redirect to sign-in; JSON clients receive
401. Invalid API credentials receive 401; missing scope receives 403. Responses
are private and not cached. `/docs`, `/docs?format=json` and `/docs.json` keep their
existing dashboard behavior, runtime information and catalog refresh.

```sh
curl "$MULTILLM_BASE_URL/openapi.json" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Accept: application/json"
```

The relative server URL uses the gateway origin. No configured origins, provider
credentials, live model catalog, account management paths or future disabled APIs
are included. The endpoint does not refresh catalogs, call providers, generate
output or reserve generation budget. Reading it does not enable any feature.

## Runtime boundaries

The managed routes cover OpenAI-compatible Chat, Responses, image generation and
model discovery, Anthropic Messages and the existing local token estimate.
Managed generation normally uses `provider:model` or a saved route ID. Stateless
protocol bridges cannot represent every provider feature: unsupported fields may
return 400. Responses continuation storage is not promised by this contract.

Each operation has `x-multillm-runtime` metadata. Managed routes and this endpoint
are forwarded from the Worker to Flask. Native OpenCode routes use the existing
Worker native handler only when `OPENCODE_EDGE_FETCH=true`; otherwise Flask handles
them. The Codex image example uses the existing direct Worker handler. These
native client paths require administrator route permission under the current
provider access policy. Their request/response schemas are deliberately open:
use the selected provider's contract and unprefixed model IDs. The examples are a
bounded selection, not an inventory of every provider route. Native availability
still depends on configuration, permission and actual provider support.

The contract documents existing controls and optional response metadata. Header
absence does not mean a feature ran or cost was zero. A native route does not
inherit managed repair, cache, cascade or quality checking from this document;
existing authentication and outbound policy still apply.

## Explicitly enabled and disabled examples

Existing managed Chat caching is bypassed without a request opt-in. To request it,
add `X-MultiLLM-Cache: on`; `refresh` requests a new result. Eligibility checks,
deployment configuration, TTL and memory bounds still apply. `off` bypasses it.
For managed tool repair, `X-MultiLLM-Tool-Repair: off` disables the existing repair
behavior on that request; `repair` requests bounded repair, and `full` can incur
another generation. Image quality checking is off unless requested with
`X-MultiLLM-Image-QA: on` or an explicit body option; `off` disables it when no body
option overrides it. Judging and repeated image generation can incur extra cost.
This feature adds no new environment keys or default generation behavior.

```sh
curl "$MULTILLM_BASE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $MULTILLM_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-MultiLLM-Cache: off" \
  -H "X-MultiLLM-Tool-Repair: off" \
  -d '{"model":"provider:model","messages":[{"role":"user","content":"Hello"}]}'
```

Replace the model placeholder with a permitted model from `/v1/models`.

## Errors, cost and retention

JSON errors may use the gateway string-error envelope or an OpenAI nested error.
Managed Messages errors use Anthropic's envelope. Native errors remain
provider-defined and may be text. Streaming Chat uses SSE data frames; Responses
and Messages use named SSE events. An error can arrive after HTTP 200, and EOF
alone is not proof of successful completion. Handle failure events without
automatically replaying a request that may have produced output. `Retry-After`
does not grant retry permission.

Existing body limits, scopes, rate limits, model permissions and budgets apply.
Prices and token estimates are not billing receipts. The local token-count path
reports `X-MultiLLM-Token-Count: estimate`; it does not call provider tokenizers.
The contract makes no zero-content-retention promise. Existing cache, media,
usage and provider retention settings remain authoritative. Contract tests do not
certify live provider capabilities, billing, Worker deployment or uptime.

## Snapshot maintenance

`services/openapi_spec.py` is the sole generator for `docs/openapi.json`. It reads
only static descriptors and uses sorted keys, two-space indentation and a final
newline. It needs only the Python standard library. From the repository root:

```sh
python -I services/openapi_spec.py > docs/openapi.json
```

`tests/test_openapi.py` compares the committed snapshot byte-for-byte with the
generator, checks local references and error schemas, and verifies registered
Flask methods and reviewed Worker routing boundaries. Review descriptors before
regeneration; add later APIs only when their runtime integration is supported.
