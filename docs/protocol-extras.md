# Source-scoped protocol extras

`PROTOCOL_EXTRAS_ENABLED` defaults to `false`. An empty value also disables the
feature. Invalid values disable it and produce one warning containing the
variable name, without its value. When disabled, existing strict translation,
namespace handling and raw request and response bytes remain unchanged.

Enable the option with `PROTOCOL_EXTRAS_ENABLED=true`. Managed callers can supply
the following namespace on a Messages request:

```json
{
  "model": "provider:model",
  "messages": [{"role": "user", "content": "Hello"}],
  "max_tokens": 128,
  "_multillm": {
    "protocol_extras": {
      "source_protocol": "messages",
      "fields": {"top_k": 7}
    }
  }
}
```

The gateway validates the source against the originating managed protocol and
holds approved extras separately from the Chat pivot body. The namespace is
internal metadata and must never be serialized to a provider. Returning to
Messages can restore `top_k` only when the selected provider explicitly admits
that field. A Responses target omits it. Provider admission defaults to an empty
set; a protocol name alone does not establish model support.

With the feature disabled, omit `_multillm` and send ordinary protocol fields:

```json
{
  "model": "provider:model",
  "messages": [{"role": "user", "content": "Hello"}],
  "max_tokens": 128
}
```

## Reviewed fields and bounds

Request extras allow only these scalar members:

| Source | Fields | Values |
| --- | --- | --- |
| `messages` | `top_k` | Integer from 0 to 2,147,483,647 |
| `responses` | `truncation` | `"disabled"` only |
| `chat` | `seed` | Signed 64-bit integer |
| `chat` | `logprobs` | Boolean |
| `chat` | `top_logprobs` | Integer from 0 to 20 |

Native JSON response extras allow Messages `stop_sequence` (null or a string up
to 1,024 characters), Chat `system_fingerprint` (null or an identifier up to 256
characters), and Responses `service_tier` (`auto`, `default`, `flex`, `priority`,
or `scale`). These response observations do not select a billing tier. Response
fields require the same source and explicit admission before restoration.

The namespace allows only `protocol_extras`, with exactly `source_protocol` and
`fields`. At most 32 fields and 16 KiB of compact UTF-8 JSON are accepted. The
reviewed allowlist is smaller than the field-count ceiling. Nested objects,
executable payloads, credentials, unknown fields and unknown namespace options
are rejected. Conflicting values in the body and extras are rejected. Automatic
truncation, containers, stored response identifiers, reasoning controls and
other lifecycle semantics cannot be smuggled through extras. Existing strict
translator lifecycle checks also remain active.

## Errors, fidelity and retention

Invalid managed extras raise an HTTP 400 translation error with parameter
`_multillm.protocol_extras`. Error messages do not echo names or values from
untrusted fields. An upstream response attempting to supply the internal
namespace fails with HTTP 502 on a translated JSON path. Raw passthrough remains
unchanged.

Content-free conversion reports distinguish IR retention from output fidelity.
An approved field omitted from a foreign or nonadmitting target is `lossy`, with
`retained_in_ir: true` and `re_emitted: false`. A restored approved field is
`exact`. Required extras that the selected target cannot admit are rejected;
required-field policy is supplied by trusted dispatch code, not client metadata.
Reports contain fixed allowlisted paths and no field values.

The carrier lasts only for its managed operation. There is no new database,
cache, prompt logging or durable retention. Discarding the carrier discards its
extras. SSE event translation remains strict and does not retain or restore
extras. No usage, cost, retry or provider capability guarantee is added. Sampling
and log-probability settings may affect output or provider charges under the
provider's existing contract.

## Managed integration interface

`services.protocol_extras.request_to_ir` constructs a typed carrier;
`request_from_ir` emits a provider body using trusted `admitted_fields` and
`required_fields`. Keep the carrier separate while dispatch copies or optimizes
the body. `translate_managed_request` is the single-hop equivalent, including
same-protocol namespace validation. `managed_request_report` composes the same
validation and extra-field observations with conversion diagnostics.

Use these hooks at authenticated managed dispatch and conversion-report entry
points. Native managed emission must use explicit provider admission, and Chat
serialization must receive only the emitted body. Raw provider endpoints use
their existing transport. `response_to_ir` and `response_from_ir` provide the
corresponding JSON response interface; the Flask response bridge uses managed
JSON translation while preserving raw same-protocol responses.
