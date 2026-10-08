# Conversion fidelity diagnostics

Diagnostics describe the existing managed translations between `chat`,
`responses`, and `messages`. They do not change translated payloads, retry
rules, response bodies, model selection, or authorization. Without the request
header below, response headers and streamed bytes keep their existing behavior.
Native Worker traffic and raw provider routes do not gain diagnostics.

## Response headers

For a managed request, add `X-MultiLLM-Conversion-Report: 1`:

```http
POST /v1/responses
Content-Type: application/json
X-MultiLLM-Conversion-Report: 1

{"model":"opencode:kimi-k2.6","input":"Hello","metadata":{"label":"demo"}}
```

Send the normal gateway authentication header as well. Omitting the conversion
header, or using any value other than `1`, disables reporting. An enabled request
receives `X-MultiLLM-Conversion-Fidelity: exact|semantic|lossy|unsupported` and
`X-MultiLLM-Conversion-Fields`, a comma-separated list of field paths only.
For the example, `request.input` is semantic and `request.metadata` is lossy.
The fidelity header reports the worst classification across all observed hops.
Same-protocol managed traffic reports exact with an empty field list.
An exact cached Chat replay describes the current hop, which performs no new
conversion. It does not reconstruct the original upstream conversion, and
diagnostic headers are not stored in the response cache.

The fields header is capped at 2048 ASCII bytes and ends at a field boundary.
It may omit paths when the full report does not fit; fidelity still accounts
for every observed field. Paths use `[]` for array members and `*` for unknown
members. Unknown user-supplied names are never echoed. Headers contain no
prompts, output, credentials, tool names, schemas, or argument values.

## Dry run

`POST /v1/conversion/report` accepts the source and target protocol and a nested
request. It requires the normal gateway key with the `chat` scope and applies
the key's model allowlist to `request.model`.

```json
{
  "source_protocol": "responses",
  "target_protocol": "chat",
  "request": {
    "model": "opencode:kimi-k2.6",
    "input": "Hello",
    "max_output_tokens": 32
  }
}
```

A successful report has HTTP 200 and this shape:

```json
{
  "fidelity": "semantic",
  "fields": [
    {"path":"request.input","classification":"semantic","reason":"Field is represented using the target protocol's semantics."},
    {"path":"request.max_output_tokens","classification":"semantic","reason":"Field is represented using the target protocol's semantics."},
    {"path":"request.model","classification":"exact","reason":"Field is preserved."}
  ]
}
```

`exact` means preserved, `semantic` means a target representation or approximation,
`lossy` means dropped or partially represented, and `unsupported` means the
existing translator rejects the request. Responses continuation controls and
Messages containers remain unsupported. Adaptive Messages thinking is dropped;
thinking budgets mapped to reasoning effort are approximations. Unsupported
requests return the content-free report with HTTP 400. Invalid protocols or
body shapes return HTTP 400; authorization failures keep HTTP 401/403.

The entire dry-run body is limited to 1 MiB before JSON parsing; oversized bodies
return HTTP 413, including bodies without a declared content length. The dry run
performs no provider request, retry, generation, generation-budget reservation,
or provider rate-slot reservation. It has no provider generation charge and
does not verify live model availability, provider capabilities, pricing, or
token usage. There is no translated payload in the response.

## Coverage and retention

Reports use the current local translator. They describe field representation,
not whether the selected provider will honor a field. JSON responses report
observed fields, including dropped log probabilities, citations and signatures.
Multi-hop bridges combine observations rather than overwriting earlier losses.
Errors keep their existing status and body; an enabled unsupported conversion
also receives the diagnostic headers. No repair or extra generation occurs.

Streaming headers describe structural response conversion only (`response`),
since later event fields cannot be known when headers are sent. Streams are not
buffered or consumed to produce diagnostics, and a semantic streaming header
does not certify that every future event field will be preserved. Nested schemas,
metadata and tool arguments are opaque; unknown fields use a wildcard path.

Reports are held only in the request context and returned to the caller. This
feature writes no report storage or content logs and makes no changes to the
gateway's existing retention policies. Browser access to the new headers may
require deployment CORS allow/expose configuration. The Flask route forwards
through the existing Container boundary; it adds no native Worker conversion.
