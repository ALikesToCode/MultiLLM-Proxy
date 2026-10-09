# Explicit output schema validation

Set `OUTPUT_SCHEMA_VALIDATION_ENABLED=true` to enable the explicit managed request
option `multillm_output_validation`. The default is `false`; an empty setting also
disables validation. Malformed settings disable validation and log one warning
without the setting value. When disabled, the option is neither interpreted nor
removed, and requests and responses retain their existing behavior.

Send the option on managed Chat Completions, Messages or Responses requests:

```json
{
  "model": "mimo:mimo-v2.5",
  "messages": [{"role": "user", "content": "Return a JSON object with an integer count."}],
  "stream": false,
  "multillm_output_validation": {
    "mode": "strict",
    "schema": {
      "type": "object",
      "properties": {"count": {"type": "integer"}},
      "required": ["count"],
      "additionalProperties": false
    }
  }
}
```

The gateway removes only this option before dispatch. It checks the generated text
as strict JSON against the explicit schema, preserving the original successful
response bytes and headers. For Chat Completions, each choice is checked. For
Messages and Responses, text blocks are joined in their original order. There is
no protocol translation solely for validation. The option does not instruct a
provider to generate JSON; use the provider's supported response format or prompt
alongside it. Existing response format and tool options are preserved.

With `OUTPUT_SCHEMA_VALIDATION_ENABLED=false`, the same request follows the
existing path, including the option. With validation enabled but the option
absent, the request and response follow the existing path. Raw passthrough and
Worker-native routes keep their existing behavior. Worker requests forwarded to
the managed Flask endpoints use the Flask validator.

Streaming requests with the option return HTTP 400
`output_validation_requires_nonstream` before provider dispatch. Malformed options
return HTTP 400 `output_validation_invalid_option`; invalid, oversized or unsupported
schemas return HTTP 400 `output_validation_invalid_schema`. Only `mode: "strict"`
and a schema are accepted in the option. Object and boolean schemas are supported.

Malformed generated JSON, schema mismatches, oversized responses and exhausted
validation limits return HTTP 502 `output_schema_violation`. For example:

```json
{
  "error": {
    "code": "output_schema_violation",
    "message": "Explicit output validation failed",
    "reason": "schema_mismatch",
    "paths": ["/*"]
  }
}
```

Error paths retain array indexes and replace all object keys with `*`, so generated
property names cannot disclose response content. Errors omit values, schema text,
validator messages and provider bodies. Reasons include `invalid_json`,
`schema_mismatch`, `invalid_response`, `unexpected_stream`, `body_limit` and
`work_limit`. Upstream HTTP errors retain their existing status, body and headers.
An unexpected successful stream is closed without consuming its content.

The response envelope is limited to 1 MiB. Schemas are limited to 64 KiB, depth 32
and 4,096 nodes. Generated JSON is limited to depth 32 and 4,096 nodes. The product
of schema and instance node counts is limited to 100,000. Validation shares a
10,000-keyword budget and 100 ms elapsed budget across choices, with at most 64
nested keyword evaluations and 100 error paths. Time is checked between keyword
evaluations; it is not a preemptive process deadline. `uniqueItems` supports arrays
of at most 128 items to bound pairwise comparisons.

Validation uses the installed `jsonschema` package with an empty reference
registry: no network or filesystem schema retrieval is allowed. Local references
are supported; unresolved references fail validation. Draft 4, 6, 7, 2019-09 and
2020-12 are supported, with 2020-12 as the default. Nested dialect and reference
scope changes and regex keywords (`pattern` and `patternProperties`) are rejected because they
cannot reliably observe the work budget. Format annotations do not enable format
assertions. Duplicate object keys, non-finite numbers and surrounding prose are
invalid JSON. This is bounded schema validation, not a universal schema engine
for native Worker traffic.

Validation never starts a second generation. Tool repair remains separately
opt-in and retains its existing retry policy. A provider may have already charged
for a response that fails validation; a validation error does not grant permission
to retry it. The validator adds no persistent storage or content logs. Existing
retention, request accounting and provider logging policies still apply.
