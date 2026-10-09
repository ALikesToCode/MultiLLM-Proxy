# Worker Realtime WebSocket transport

Realtime bridges authenticated OpenAI-compatible sockets directly in the Worker.
It does not start the Container. `REALTIME_ENABLED` is off by default; an unset,
empty, false or malformed value preserves existing route handling. A malformed
provider mapping disables Realtime and warns once without printing its value.

Enable it with `REALTIME_ENABLED=true` and an exact model mapping:

```json
{"openai:realtime-model":{"url":"wss://approved.example/v1/realtime?model=realtime-model"}}
```

Set this JSON as `REALTIME_PROVIDERS_JSON`. Every URL must use WSS, a public DNS
hostname and port 443. The mapping supplies the complete upstream URL, including
any provider model query. Client URLs, query fields, hosts and credentials never
select an upstream. Redirects are refused. OpenAI, OpenCode, LinkAPI, Codex Easy,
NanoGPT, OpenRouter, Groq and xAI use their existing Worker provider key bindings
with Bearer authentication. Configure only providers whose socket contract uses
that authentication. No caller header reaches upstream except the exact
`OpenAI-Beta: realtime=v1` version header. Upstream headers are not returned.

Connect with `GET /v1/realtime?model=openai:realtime-model`, `Upgrade: websocket`
and `Authorization: Bearer <gateway key>` or `X-MultiLLM-API-Key`. The bootstrap
gateway key, verifiable D1 dashboard keys and D1 integration keys are accepted.
Dashboard model grants, expiry, revocation and IP controls apply. Both `chat` and
`audio` scopes are required. Keys stored only in the Container cannot open sockets.
Each socket is authorized at admission; revoking a key stops later admissions,
including tickets. Already-open sockets expire within 15 minutes.

With Realtime enabled, invalid upgrades return JSON 426, absent or invalid keys
return 401 and insufficient scopes or model grants return 403. Unsupported models
return 403. Missing storage, migrations, price evidence, monetary ceilings or
admission authority return JSON 503 before dialing. A full session or budget limit
returns 429. Upstream handshake failure returns 502; no automatic retry occurs.
With Realtime disabled, `/v1/realtime` keeps the existing Container handling.

## Cost admission

`REALTIME_SESSION_CAP_USD` must be positive. `REALTIME_PRICING_JSON` maps each
exact model to prices per million tokens and a provider-enforced session ceiling:

```json
{"openai:realtime-model":{"input_text":1,"output_text":2,"input_audio":3,"output_audio":4,"provider_session_limit_usd":0.10}}
```

These numbers are illustrative, not a provider price quotation. The provider
ceiling must be enforced by an independently verified upstream account or session
contract and must be no greater than the gateway cap. Ordinary usage events arrive
after generation and cannot enforce a hard monetary ceiling themselves. Do not
configure an estimated cost as `provider_session_limit_usd`. If the upstream has
no enforceable ceiling, leave it unset: admission refuses the session. Operators
must verify that the ceiling includes every billed activity, including transcription.
The gateway cannot discover or certify a provider's billing contract from a socket.

The entire ceiling is reserved through durable usage reservations before dialing.
Key daily/monthly budgets apply; otherwise set a positive
`REALTIME_DAILY_BUDGET_USD`. Existing unknown holds still reduce available budget.
Known final audio/text usage uses the supplied prices. Cached input requires
`cached_text` and `cached_audio` prices plus the provider's modality breakdown.
Partial, inconsistent, unpriced, interrupted or in-flight usage retains an unknown
hold instead of inventing a zero bill. Unpriced transcription remains unknown.
The usage ledger stores measured aggregate tokens and nullable cost. Realtime
session rows also store modality counts, opaque key identity, lease and timestamps.
Storage failures retain reservation evidence for operator reconciliation.

## Lifetime and tickets

At most two simultaneous sockets per gateway key are admitted atomically in D1.
Enable the existing admission authority with a nonzero principal or model-group
limit and its existing binding. Its renewable lease is held until either side
closes. Sessions have a 900-second TTL, 30-second idle limit and 1 MiB frame limit.
Both text and binary frames retain their bytes. Policy violations close 1008.
Upstream error events are forwarded verbatim before closing both sides with 1011,
unless an event exposes the provider key, in which case it is withheld and the
session closes 1008. Transport failures close 1011 without fabricated events.

Optional `POST /v1/realtime/client_secrets` accepts an authenticated JSON body
`{"model":"openai:realtime-model"}`. It requires the existing `JWT_SECRET` binding
and returns `{value,expires_at}`: a gateway-scoped signed ticket, never a provider
secret. Present `value` as the Bearer token for the socket. Tickets last 60 seconds,
are restricted to that model and current credential, and are consumed atomically
once. At most 16 outstanding tickets per key may exist. A ticket cannot issue
another ticket. No credentials are accepted in URL parameters or subprotocols.

Apply migration `0029_realtime_sessions.sql` and the existing usage/admission
migrations before enabling. No prompt, transcript, audio or event content is
persisted or logged. Socket metadata and unknown holds remain until the operator's
approved retention/reconciliation process handles them. The implementation does
not claim live provider protocol, billing or WebSocket compatibility from local
fake-socket checks.
