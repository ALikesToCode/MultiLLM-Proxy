# Upstream client headers

Every provider API route defaults missing client identity to Codex, including
native Chat Completions, Responses, Messages, model catalogs, unified routes,
free-model pools, and roleplay. The same policy runs in Flask, the Worker, and
roleplay session transport.

| Header | Default | Central override |
| --- | --- | --- |
| `User-Agent` | `codex-cli` | `UPSTREAM_DEFAULT_USER_AGENT` |
| `originator` | `codex_cli_rs` | `UPSTREAM_DEFAULT_ORIGINATOR` |

Precedence is per header: nonempty caller header, then environment setting,
then the built-in default. Header names are case-insensitive. Empty or invalid
defaults fall back to the built-in value. An explicit user agent from a browser,
HTTP library, or another application is preserved, not replaced.

The defaults follow the official Codex source: the backend client's version-free
[`codex-cli` fallback](https://github.com/openai/codex/blob/4f2449b4b21988d5015ce6edf755fbd6a37a4908/codex-rs/backend-client/src/client.rs#L246)
and the HTTP client's
[`codex_cli_rs` originator](https://github.com/openai/codex/blob/4f2449b4b21988d5015ce6edf755fbd6a37a4908/codex-rs/login/src/auth/default_client.rs#L39).
The service does not invent an installed Codex version, VM operating system,
account ID, or credential. Headers identify the client; they do not grant provider
access, increase quota, or change the provider's allowed usage.

## Per-request override

Send either header normally; no model or endpoint change is needed:

```http
User-Agent: my-client/1.0
originator: my-client
session-id: vm-session-123
thread-id: conversation-456
```

For a fleet-wide change, set the two environment variables on the service.
Cloudflare deployments must set them on the Worker; they are forwarded to its
Container. A local `.env` alone does not change a deployed Worker.

## Conversation continuity

Native Codex `session-id` and `thread-id` are forwarded unchanged. Legacy
`session_id`, `x-session-id`, `x-codex-session-id`, and `x-session-affinity` are
also preserved.

Only OpenCode receives `x-opencode-*` headers. Its session is selected in this
order: explicit `x-opencode-session`, `thread-id`, `session-id`, `session_id`,
`x-session-id`, `x-codex-session-id`, then `x-session-affinity`. Thread ID takes
priority so separate conversations on one VM do not share a provider session.
Explicit `x-opencode-client`, `x-opencode-project`, and `x-opencode-request`
are preserved on OpenCode routes.

Roleplay uses its existing credential-scoped conversation ID when none of those
session headers is supplied. Overrides are per turn and follow that turn through
fallback, continuation, and compaction; they are not saved as session defaults.
Other OpenCode routes also supply `x-opencode-session` when the caller sends no
session headers. Before dispatch, the proxy derives an opaque, credential-scoped
HMAC from a body `session_id`/`conversation_id` (including metadata and Responses
`conversation`), or from the opening messages through the first user input.
Responses string input and Anthropic Messages are supported. Added turns, output
parameters, and model switches do not change an unchanged opening's ID.

This is best-effort affinity, not reconstructed conversation state. Identical
openings under the same credential can share affinity; changing or dropping the
opening can change it. Explicit conversation IDs remain the reliable option.
No prompts, keys, or generated IDs are stored by this fallback. It does not use
one fleet-wide ID, an IP address, or a raw credential as the session header.

Discovery is bounded to 1 MiB of JSON; the direct Worker path only probes declared
JSON bodies with a known length and limits discovery to one second. Unknown-length
uploads stream immediately. Missing, oversized, or unreadable input receives a unique ID for
that logical request. Provider retries retain that ID. Request and response bodies
remain unchanged. Other providers do not receive these inferred OpenCode headers.

Existing authentication, billing, model selection, request bodies, and roleplay
provider availability are unchanged. This forwarding policy does not include
cookies or account credentials. Browser preflight allows the identity and
session headers, though a browser may control its own `User-Agent`.
