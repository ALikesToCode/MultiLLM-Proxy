# Outbound secret firewall

Request content is checked before provider dispatch. `SECRET_SCAN_DEFAULT` accepts `off`,
`observe`, `redact` (default), or `block`. A dashboard account can override the default
with its key controls. `redact` replaces only high-confidence matches; heuristics are
observed. `block` rejects high-confidence matches with HTTP 422 / `secret_detected` and
counts by type. Knowledge always uses `block`, except for an effective `off` mode.

## Detector contract

`services/secret_scan.py` exposes `scan_text`, `redact_text`, `scan_payload` and
`redact_payload`. `worker/secret-scan.mjs` exports their camel-case equivalents. Findings
contain type, confidence and Unicode code-point offsets. Reports contain `high`,
`heuristic`, `types`, at most 20 JSON `paths`, and `truncated`. Redaction returns a copy
only where needed, leaves its input intact, and uses
`[REDACTED:<type>:<first six SHA-256 hexadecimal characters>]`.

Both runtimes load the same precise format patterns from `worker/secret-patterns.json`.
Private-key blocks use one bounded BEGIN/END marker pass; a new BEGIN replaces an
unterminated marker so malformed pasted text cannot hide the next complete key. A portable,
synchronous SHA-256 helper keeps the Worker API synchronous without Node-only imports.
Shared synthetic vectors concatenate credential prefixes and payloads at runtime.

Recognized formats: PEM private keys; AKIA/ASIA access IDs; GitHub classic and fine-grained
tokens; Anthropic and OpenAI project/legacy keys; Google API/OAuth tokens; Slack tokens and
webhooks; Stripe live keys; npm and Hugging Face tokens; Telegram bot tokens; JWTs; URLs
with embedded passwords; and `mllm_intelligence_` integration credentials. Dashboard keys
are unprefixed random 32-character alphanumeric strings, so no precise standalone format
can distinguish them from ordinary text. They are detected heuristically in secret fields
or assignments, rather than redacting arbitrary random prose.

Assignments and JSON/YAML secret fields need 12 characters and Shannon entropy of at
least 3 bits/character. Examples, placeholders, repeated-character values, UUIDs, data
URLs, image/audio base64 leaves and sha512 lockfile integrity strings are excluded.
Overlapping matches prefer the high-confidence format. Heuristics are never redacted.

Each payload has a 4 MiB UTF-8 string-leaf budget, 100,000 visited nodes, depth 64 and
4,096 candidate findings per leaf. Reports mark budget/depth/node limits as truncated.
Multipart and URL-encoded form inspection considers at most 256 text parts; binary file parts remain untouched.
The edge buffers at most 32 MiB and waits at most one second for body consumption. Larger,
stalled, malformed-binary or otherwise uninspectable bodies follow the original dispatch
path. Detector/audit failures fail open and log only a fixed message or exception type.
Scanning a bounded prefix cannot guarantee secrets beyond that prefix are caught.

## Dispatch coverage

| Boundary | Covered routes/content |
| --- | --- |
| `ProxyService._make_base_request` / `_make_request_with_timeout` | Unified chat, messages and responses; generic `/<provider>/<path>` routes; optimize summarization/final generation; free fallback pools; images/edits; audio speech, transcription/translation text; narration; media probes; internal batch items; dashboard OpenRouter chat; gateway MCP tools through REST |
| `AdapterTransport.start` | Intelligence chat and media; scan on the caller thread before its background exchange |
| `cloudflare_ai.post` | Cloudflare AI text/image/audio requests before the private Worker binding dispatch |
| `video_generation._send` | Video JSON/multipart generation and provider JSON requests |
| `firewallFetch` in the edge | Direct OpenCode, LinkAPI and Codex-easy handlers; roleplay generation, retries and compaction dispatched outside the Container |
| Knowledge client / edge / private service ingress | `/v1/knowledge/*`, `/mcp` tool arguments, native provider tools and retrieval/Alexandria fan-out |

Kimi Code uses the Container; it has no direct edge provider dispatch. Container-forwarded
requests are not scanned at the edge. Cloudflare AI requests use the Container check
before the private AI binding; the binding does not repeat it. Media downloads/uploads,
OAuth exchanges, control-plane RPC, credential discovery and model-catalog reads do not
carry prompt bodies and are excluded.

Python checked-byte markers preserve the caller-thread decision across an intelligence
exchange. A request-local cache (32 entries, 8 MiB total) reuses identical retry bodies.
Deliberate roleplay blocks stop before provider or local-compaction fallback. Roleplay aggregates compaction and generation findings into its response header; streaming headers cover dispatches made before the stream opens. Knowledge checks arguments before any fan-out, cache or evidence persistence, rather than
scanning each provider's later wrapper. Its private envelope carries the effective
`secret_scan_mode` and `secret_scan_checked` marker; only the private binding can submit
that envelope. A direct private-service caller without the marker is checked there.

Coverage tests freeze every Flask route declaration, including dynamic registration
expressions, edge route literals/module names, and reviewed dispatch/guard counts. Any new route or dispatch requires
updating the inventory after checking its boundary. Focused guard assertions and mocked
provider-byte tests accompany this conservative review gate; the inventory alone is not
proof of every request transformation.

## Audit and operator controls

An event contains timestamp, key identity, route, provider when known, effective mode,
action and counts. No secret, excerpt, path or full hash is stored. Successful replies
with findings carry `X-MultiLLM-Secret-Scan: redacted=N; observed=N`. Gateway MCP carries
the internal REST counts outward and propagates deliberate secret blocks as HTTP 422.

Migration 0010 restricts physical audit actions. To keep it immutable, scan records reuse
`setting_change` with `kind: secret_scan` in bounded JSON metadata. Audit reads project
these as `secret_scan`, and `/admin/audit` includes the latest 50 decisions. Existing
sign-in/out metadata limits remain 512 characters; scan metadata is bounded at 1024.
Audit failure never prevents a generation or intentional block. Edge audit waiting is
bounded to one second; Container auditing uses the existing bounded private RPC.

Parallel image tasks carry the caller's key controls into their copied contexts and
aggregate response counts back to the parent. Secret blocks stop image candidate fallback.
Batch APIs retain their existing partial-result envelope: blocked items report 422 and
`secret_detected` without dispatch, while the enclosing batch can still return HTTP 200
for other completed items.

The existing key controls are fixed SQL columns, not a JSON document. Additive migration
`0011_secret_firewall.sql` adds nullable `control_users.secret_scan_mode`; SQLite account
schema initialization also adds the column. D1 reads preserve all pre-0011 controls with
a null override; writes of an override require migration 0011. Older pre-0007 accounts
keep their existing compatibility path. Backup serialization preserves the override.

## Validation and rollout

Synthetic cross-runtime vectors cover every supported type, exclusions, stable
placeholders, modes, Unicode byte budgets, multipart binary preservation, route coverage,
mocked Flask/edge upstream bytes, audit secrecy and a bounded one-megabyte scan.
Existing Python, Worker and Knowledge suites provide broader transport/control regressions.
No production calls, deployment or remote migration are part of local verification.

Before deployment apply migration 0011 to `multillm-intelligence` through the normal
approved migration flow, then deploy edge, Container and Knowledge together so private
envelope fields agree. `SECRET_SCAN_DEFAULT` is optional; absence means `redact`.
The Knowledge Worker adds an `INTELLIGENCE_DB` binding to the existing audit database for unchecked private ingress. No new database or Durable Object migration is required. Operators should choose `off`
only when deliberate secret transmission is required, and should account for finite
scan limits and fail-open behavior when interpreting audit absence.
