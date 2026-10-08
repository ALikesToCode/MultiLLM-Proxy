# Configuration-bound capability probes

This operator command observes tool-call structure, JSON schema output and optional
synthetic vision through an explicitly selected Flask or Worker gateway. It never
changes routing, catalogs, health, configuration or stored state. It imports no app
initialization or provider discovery code. There is no background job or feature flag.

## Plan first

Prepare a non-credential JSON descriptor of the **effective** configuration:

```json
{
  "runtime": "flask",
  "gateway_base_url": "http://127.0.0.1:5000",
  "provider": "example",
  "model": "example-model",
  "base_url": "https://provider.example/v1",
  "credential_revision": "credentials-r1",
  "provider_header_revision": "upstream-headers-r1",
  "policy_revision": "policy-r1",
  "headers": {},
  "capability_config": {"tools": true, "reasoning": {"enabled": false}}
}
```

All ten fields are required. `gateway_base_url` is the gateway root (optionally with
an installation path prefix), not its `/v1` endpoint. `base_url` is the configured
upstream provider URL. HTTPS is required except for explicit loopback HTTP URLs.
URLs cannot contain credentials, query strings or fragments. Routing aliases and
provider-prefixed model identifiers are refused. The model is sent as the exact
`provider:model` to `/v1/chat/completions`; no model-name inference is performed.

`headers` contains only non-credential request headers actually sent to the gateway.
Header names are case-insensitive in the configuration digest; values are preserved
exactly. Authentication, cookie, framing and transport-controlled headers are
refused. Use `provider_header_revision` for the complete upstream header snapshot
that the gateway constructs, including revisions of any sensitive headers.
`capability_config` records all other effective settings relevant to the observation,
including compatibility transformations and provider billing settings. Do not put
keys, credentials, prompts or responses in this descriptor. The credential revision
is an operator-maintained opaque identifier for the effective gateway and upstream
credentials; it must change on rotation without containing or hashing a key.

The command does not fetch configuration from the running gateway. The operator
must keep the descriptor synchronized with that configuration. A digest binds the
observation to the supplied snapshot; it cannot detect an unreported live change.

Provide a versioned synthetic fixture selector in a separate JSON file:

```json
{"synthetic": true, "fixture_version": "synthetic-v1", "tool_call": true, "json_schema": true}
```

Tool and schema selectors send fixed synthetic requests for `{"status":"ready"}`.
There is no arbitrary prompt input. Vision is absent unless a fixture is provided.
For vision, set `vision` to `{"image_data_url": "...", "expected": "red"}`. Obtain
the canonical one-pixel PNG data URL from `synthetic_image_data_url("red")` in
`services.capability_probes`; green and blue are also supported. Only these exact
synthetic images with their matching expected color are accepted. External URLs,
arbitrary image data, additional fixture fields and non-synthetic selectors are refused.

```sh
python scripts/model_capability_probe.py --config capability-config.json --fixtures synthetic-fixtures.json
```

The default prints a dry-run JSON plan with **zero calls**, zero incurred cost and
no observations. No gateway key is read in dry-run mode. The planned HTTP request
count and actual sending count appear on stderr before any dispatch; stdout remains
one JSON document. Dry-run receipts cannot be treated as measured capabilities.

## Explicit execution

Both `--execute` and `--allow-generation` are required. A single flag is a refusal.
Supply the gateway key through your secret manager in `MULTILLM_API_KEY`, or choose
another existing environment variable name with `--key-env`. No key argument,
credential file, dotenv loading or key logging is supported.

```sh
python scripts/model_capability_probe.py --config capability-config.json --fixtures synthetic-fixtures.json \
  --execute --allow-generation --input-usd-per-million 0.10 --output-usd-per-million 0.20 \
  --max-requests 4 --max-output-tokens 64 --max-input-tokens 4096 --max-cost-usd 0.01
```

Set `runtime` to `worker` and use the Worker gateway root for the Worker adapter.
Both adapters use the same explicit model route and bounded JSON contract. They
send no redirects, HTTP retries, model-list requests, token-count requests or
follow-up tool executions. Each selected capability makes one independent request.
The entire plan must fit the request and reserved cost limits before the first call.

Defaults and hard bounds:

| Option | Default | Accepted bound |
| --- | --- | --- |
| `--max-requests` | 4 | 1–32; currently at most three fixture checks |
| `--max-output-tokens` | 64 | 1–1,024 per request, sent as `max_tokens` |
| `--max-input-tokens` | 4,096 | 1–65,536 billable input tokens per request |
| `--max-cost-usd` | 0.01 | 0–1,000,000 USD, at most 12 decimal places |
| `--timeout-seconds` | 10 | Greater than 0, at most 30 per socket operation |

Each request is at most 32 KiB and each response at most 64 KiB. JSON document inputs
are bounded to 64 KiB. A serialized request plus a 256-unit framing allowance must
fit the input allowance. This byte check is conservative for these fixed text
fixtures; it is not a native tokenizer or a proof of multimodal billing limits.

A known effective input **and** output price is mandatory before any generation.
Explicitly known zero rates are valid; missing, partial, negative or nonfinite rates
are refused. Monetary inputs are at most 1,000,000 with at most 12 decimal places;
this bound prevents decimal underflow or rounding from bypassing the paid cap. Reserve the full input allowance and output ceiling for every planned
request using decimal arithmetic. Failed and unknown-usage attempts still consume
that reservation. Rates and allowances must cover runtime premiums, reasoning and
image billing. If the provider has unbounded or separately billed charges that
cannot be covered by these conservative token-equivalent bounds, do not execute.
This command cannot enforce provider billing or stop an already generated response.

Reported usage exceeding either token bound, malformed usage, redirects, transport
failures, authentication/billing failures, rate limits and server errors stop further
checks. There is no retry of a request that may have produced output. The timeout is
per socket operation, not a total run deadline. The request count is gateway HTTP
attempts; gateway-internal retries or transformations depend on the supplied effective
configuration. Use settings that avoid extra provider attempts when applying a paid cap.

## Interpret and retain receipts

Observations are `supported`, `unsupported` or `inconclusive`:

- `supported` means the exact fixture output contract was observed: a named function
  call with a nonempty ID and valid arguments, the exact JSON schema value, or the
  supplied synthetic pixel color.
- `unsupported` requires an explicit 400/422 feature rejection code and matching
  parameter. A generic error or an unavailable model does not prove lack of support.
- Malformed output, duplicate JSON members, truncation, fixture mismatch, missing
  response structure or transport failure is `inconclusive`. No successful response
  is fabricated. A wrong pixel color does not establish that vision is unsupported.

Receipts include provider, model, runtime, configuration digest, policy revision,
fixture version/digest, UTC timestamp, planned and attempted request totals, token
totals, price inputs, conservative reservation and observations containing only
bounded reasons and HTTP status. Raw URLs, header values, credentials, fixture
contents, prompts, model responses and exception messages are omitted.

`cost_usd` uses reported usage at the operator-supplied rates; it is not a billing
receipt. Missing input or output totals remain independently null. Any missing or
invalid usage makes total cost null, while `reserved_cost_usd` remains available.
Unknown usage never means free generation. Interrupted runs keep attempted counts,
partial observations and a stop reason; unsent probes are not labeled supported.

`receipt_is_current(receipt, config, fixtures)` refuses dry runs and checks exact
provider/model/runtime, canonical configuration digest, policy revision and fixture
binding. A changed upstream or gateway URL, model, provider, request header value,
credential/header revision, capability setting or policy revision makes the old
receipt stale. Object key ordering and header-name casing do not. A fixture change
also invalidates the receipt even if its version label was reused. Receipts are
unsigned local observations, not proof of model identity or provider authenticity.

By default the receipt goes to stdout; retain it only as long as needed under your
operator policy. `--output new-receipt.json` creates a new file exclusively and
refuses existing files **before** sending requests. No automatic persistence, catalog
promotion or routing eligibility change occurs. Keep locally retained receipts
private as provider/model identifiers may reveal deployment choices. Provider-side
retention of the synthetic requests follows the configured upstream policy.

Exit status follows the operator scripts: 0 for a valid dry run or completed checks
with decisive observations (including explicit unsupported results); 1 for an
inconclusive/interrupted run or file/operation failure; 2 for invalid input, missing
opt-in, unavailable pricing/credentials or a rejected budget. An incomplete output
file may remain if an operation fails after exclusive file creation.

Tests exercise the CLI and both adapters with fake transports/connections. They do
not certify live model support, actual gateway configuration, billing or deployment.
