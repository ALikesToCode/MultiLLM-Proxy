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
Other routes leave a missing session ID absent. There is no fleet-wide static
session ID and no new random session on every retry.

Existing authentication, billing, model selection, request bodies, and roleplay
provider availability are unchanged. This forwarding policy does not include
cookies or account credentials. Browser preflight allows the identity and
session headers, though a browser may control its own `User-Agent`.
