# Provider authenticity and conformance diagnostics

Run this external operator CLI against a deployed Worker or Flask gateway. Use an
existing gateway key made available privately as `MULTILLM_API_KEY`. The CLI reads
that variable only; it accepts no key argument and reads no environment file or
credential store. Normal gateway authentication and model entitlements still apply.

```sh
python scripts/provider_authenticity.py \
  --base-url https://gateway.example --model nanogpt:example-model
```

The default sends one `GET /v1/models` and no generation request. Catalog names
are claims, so a listed model produces an `unknown` verdict with
`claim: model_identity`, `generation_requests: 0`, `coverage: [catalog_claim]`
and `identity_not_verified` in its limitations. Missing or malformed catalog
entries and HTTP or transport failures remain inconclusive. They prevent
subsequent generation, including when generation was allowed.

## Explicit generation

```sh
python scripts/provider_authenticity.py \
  --base-url https://gateway.example --model nanogpt:example-model \
  --allow-generation
```

This permits one catalog request and at most two nonstreaming
`POST /v1/chat/completions` requests. Each Chat request asks the model to echo a
fresh, independent synthetic nonce with `max_tokens: 64`. No user conversation
is accepted. An observed contradiction ends the run early. There are no retries,
redirects, generation failovers or background probes initiated by this tool.
Existing server-side provider transport behavior is unchanged; the CLI request
budget does not count any internal gateway transport attempts.

Before dispatch, a JSON plan is printed and flushed to stderr. It gives the
maximum request count, generation count, output token caps (128 total), timeout,
response size bound and `projected_cost: null`. Null means the provider price is
unknown, including for metadata. Generation may cost money; the token cap does
not establish the amount billed. The tool makes no paid or billed assertion.

Every request uses a 10-second Requests connect/read timeout. Response reads also
check elapsed time between chunks and stop after 256 KiB. These checks cannot
interrupt a synchronous read already in progress, so the timeout is not a hard
10-second wall-clock deadline. Responses are closed exactly once, including on
HTTP rejection, malformed JSON, oversize bodies and read errors. The default
client disables ambient netrc authentication and environment proxy settings,
uses normal TLS verification, and has zero automatic retries.

## Interpreting the JSON

Stdout contains one JSON report. Only fixed observation fields, request indices,
HTTP status codes, schema booleans, nonnegative usage counts, nonce booleans,
SHA-256 hashes and safe limitations are retained. Raw prompts, completions,
model-name strings, response extras, headers, URLs and exception text are omitted.
Nothing is saved; shell redirection is an operator choice. The service imports
no gateway configuration, credential pool, catalog storage or routing handler.

`claim: chat_protocol_conformance` describes the synthetic nonstreaming contract:

- `supported`: both responses have the expected Chat envelope, echo their own
  nonces, report complete plausible usage, and have consistent envelope and
  model-claim fields. This applies only to those observations.
- `contradicted`: the report names a narrow violated contract in
  `contradictions`, such as `chat_envelope_schema`, `chat_json_envelope`,
  `usage_plausibility`, `synthetic_nonce_echo` or
  `repeated_model_claim_consistency`. `coverage` shows the observed signals.
- `unknown`: catalog or probe evidence was unavailable or insufficient. Missing
  or partial usage stays unknown; truncated or filtered output is insufficient
  for the nonce contract. HTTP rejection and timeouts never become successes.

The Chat envelope requires a nonempty id and model claim, `chat.completion`, a
nonnegative integer creation time, and one choice at index zero with an assistant
text message and a standard text finish reason. Usage checks reject booleans,
strings, negatives, zero input counts or zero output counts for nonempty output,
a completion count exceeding the requested cap, and a total
that differs from the sum of input and output counts. Counts are provider claims,
not receipts or tokenizer evidence. Partial counts are retained only when valid.
No comparison assumes repeated prompts consume identical token counts: the two
nonces differ.

A returned model name, consistent hash or successful nonce echo never verifies
hidden model identity. All reports retain `identity_not_verified` and
`billing_not_verified`. A different response model name is labeled
`model_claim_differs`; a stable alias can still conform to Chat. Self-identification
is not used. There is no heuristic provider grade or subjective quality score.
Tokenizer-delta probes are deferred until native counting is available and
explicitly selected; local estimates supply no model-family evidence.

Exit codes are `0` for supported observed conformance, `2` for a contradiction,
`3` for inconclusive evidence, and `1` for CLI or configuration errors.

## Targets and scope

Supply an explicit lowercase `provider:model` identifier. Automatic, free-pool,
intelligence and cascade routing identifiers are rejected. The identifier is
forwarded unchanged so the gateway can enforce access before dispatch.

HTTPS is required. Userinfo, query strings, fragments, control characters,
backslashes and dot-segment paths are rejected. A deployment path prefix is
retained before `/v1/models` and `/v1/chat/completions`; supply the gateway base,
not an endpoint ending in `/v1/models`.

For a local gateway only, explicitly pass `--allow-loopback-http` with
`http://localhost:5000`, a loopback IPv4 address or `http://[::1]:5000`. The flag
does not permit remote plaintext HTTP.

The diagnostics do not change live routing, credential health, capability
policies, provider credentials, dashboards or storage. Offline tests inject fake
transports. Live probes require separate operator authorization.

## README handoff

Operator diagnostics provide bounded, content-free provider conformance and authenticity signals.
