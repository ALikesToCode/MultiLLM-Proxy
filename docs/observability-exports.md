# External observability exports

The gateway can send content-free request observations to explicit Langfuse and
Helicone collectors. `OBSERVABILITY_EXPORTERS_JSON` defaults to `[]`, which sends
nothing. An unset or empty value also disables export. Malformed JSON, unsupported
exporter types, unknown fields or invalid destinations disable all exporters and
produce one warning without the setting's value.

Configure each destination with exactly these fields:

```json
[
  {
    "type": "langfuse",
    "endpoint": "https://langfuse.example/api/public/ingestion",
    "allowed_origins": ["https://langfuse.example"],
    "credential_env": "LANGFUSE_EXPORT_CREDENTIAL"
  },
  {
    "type": "helicone",
    "endpoint": "https://helicone.example/custom/v1/log",
    "allowed_origins": ["https://helicone.example"],
    "credential_env": "HELICONE_EXPORT_CREDENTIAL"
  }
]
```

Replace the example destinations with the collector ingestion endpoints you
operate. There are no implicit hosts or fallback destinations. Endpoints must use
HTTPS and match an exact configured origin, including a non-default port. Wildcards,
URL credentials, query strings, fragments and redirects are refused. Origin entries
have no path beyond `/`. Configuration is limited to 32 KiB, eight exporters and
sixteen origins per exporter. Duplicate destinations with the same type and
credential reference are invalid.

`credential_env` names a private environment variable whose name ends in
`_EXPORT_CREDENTIAL`, so a provider or administrator secret cannot be sent to a
collector by mistake. For Langfuse its value is
the public key and secret key joined by a colon; it is encoded as HTTP Basic
authentication at delivery time. For Helicone its value is the collector token,
sent as HTTP Bearer authentication. Values appear only in outbound authentication
headers. They never appear in configuration examples, export bodies, status or logs.
An absent or empty credential causes a delivery failure without an HTTP call.
The Flask Container must receive the configured credential variables through its
explicit environment allowlist. Configure Worker bindings separately.

Observations contain request and correlation IDs, a hashed principal identifier,
the selected authorized model, request kind, status, a fixed error classification,
timings, nullable token counts, nullable cost, and usage/cost provenance. They never
include prompts, generated output, tools, API-key prefixes, raw request or response
headers, arbitrary metadata or upstream error messages. Model names come from
trusted finalization metadata. Zero token counts and zero costs remain distinct
from unknown values. Usage provenance remains `unknown` when unavailable; no price
is inferred from a collector response. Shadow and canary observations retain their
own kind and cost instead of being folded into production request totals.

Langfuse receives `generation-create` ingestion events with stable IDs and the
observation in generation metadata. Helicone receives content-free custom log
envelopes, split seconds/milliseconds timing, and the observation as the
`Helicone-Property-observation` property. The structural provider URL is the neutral
`https://multillm.invalid`; it is never used for a generation or network request.
Collectors requiring prompt/output fields cannot use this export mode. There is
no content-capture option.

Each process or Worker environment has an in-memory queue of at most 1,000
observations. Delivery takes at most 50 observations per batch; Helicone's custom
endpoint uses one HTTP envelope per observation. Every delivery attempt has a
two-second timeout and at most two retries, limited to transport failures, HTTP
429 and HTTP 5xx. Redirects and other HTTP errors are terminal. Export retries
never invoke a generation or change its retry permission. Stable event IDs are
reused on collector retries, but remote duplicate suppression depends on the
collector. The queue holds no durable telemetry: restarts or Worker eviction can
lose accepted records. No D1 or R2 table is created for exports.

Flask submissions only enqueue; a daemon thread delivers them independently of
OTLP. The existing OTLP payloads, headers, queue, return values and configuration
remain unchanged with exporters enabled or disabled. Native Worker finalization
enqueues its own observation and schedules export with the request execution
context's `waitUntil`. Forwarded requests export from Flask; their private D1
ledger flush never exports again. Worker collection and scheduling require the
native finalization hook to supply that execution context. Without scheduling,
acceptance only buffers the observation until an explicit flush.

`OBSERVABILITY_EXPORTER.status()` in Flask and
`getObservabilityExporter(env).status()` in the Worker return accepted, queued and
dropped counts. Each exporter reports its type, credential variable name,
attempt count, acknowledged count, failed count and delivery status (`idle`,
`acknowledged`, `partial`, `failed` or `credential_unavailable`). These are internal
operator interfaces, not new public endpoints. Queue acceptance is **accepted**,
never delivered. A 2xx HTTP acknowledgement indicates collector acceptance, not
proof of persistent storage. Langfuse HTTP 207 receipts count only successful
event IDs belonging to the submitted batch and exclude IDs listed as errors;
missing, malformed or oversized receipts acknowledge nothing. Partial receipts
are not retried. Collector response bodies and exception details are never logged.

Delivery failures are independent across exporters and do not alter generation
responses, accounting, storage or authorization. The queue drops newest items
when full and counts those drops. Deduplication retains the most recent 1,000
accepted request/owner/kind identities; it is process-local and does not promise
distributed exactly-once delivery. Content-free export is compatible with zero
content retention, but identifiers, model names, timings and usage still leave
the gateway at the operator's explicit direction. Local tests use fake collectors;
they do not establish live collector compatibility, persistence or deployment.
