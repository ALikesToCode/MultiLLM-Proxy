# OmniRoute assessment

Reviewed 2026-07-31 against OmniRoute's latest published release, v3.8.49,
the `release/v3.8.50` branch, and the current MultiLLM codebase.

## Decision

Do not replace MultiLLM with OmniRoute.

OmniRoute is broader as a local CLI gateway and exposes a large routing strategy
surface. MultiLLM has different constraints: explicit provider paths, raw
image/audio/file forwarding, provider-specific Responses transports, Cloudflare
deployment paths, and strict separation between proxy authentication and provider
credentials. Replacing those paths would create compatibility and operational
risk without removing the need for custom adapters.

The useful approach is selective adoption: copy the operator outcomes, not
OmniRoute's routing machinery.

## Adopted

### Explainable recovery states

MultiLLM now reports `closed`, `degraded`, `open`, and `half_open` on normalized
provider transports. Recovery cooldown grows after failed probes, and 429
responses are tracked as rate-limit events rather than provider outages.

Half-open recovery permits two parallel probes by default. This matters for
multiple Codex instances: one recovery request no longer blocks the second, while
the circuit still caps provider pressure.

Circuit state is intentionally process-local and resets when the application
process restarts. A multi-replica deployment therefore gets independent recovery
decisions per replica; fleet-wide coordination would require a shared state
adapter rather than pretending in-memory state is global.

Fidelity-first raw transports remain outside circuit substitution and retries so
paid or protocol-specific requests are forwarded exactly once. The dashboard and
response headers label those paths as `passthrough`; OpenCode is labeled `mixed`
because its direct native paths are raw while its normalized route is managed.

### Operational response headers

Authenticated proxy responses can expose:

- `X-MultiLLM-Provider`
- `X-MultiLLM-Model`
- `X-MultiLLM-Route-Decision`
- `X-MultiLLM-Circuit-State`
- `X-MultiLLM-Latency-Ms`
- `X-MultiLLM-Estimated-Cost-USD`
- `X-MultiLLM-Cost-Basis`

Values are allowlisted or sanitized before becoming headers and are exposed
through CORS for browser clients.

### Configured-only cost estimates

Operators may supply per-million-token prices through
`MODEL_PRICING_USD_PER_MILLION`. MultiLLM does not ship guessed prices. Requests
without matching configuration remain visibly unpriced, and estimates are labeled
as reservation-based rather than provider invoices. The estimate uses the
incoming prompt-token estimate plus the caller's requested output limit; when no
output limit is supplied, no output-token cost is invented.

### Control-plane UI

The operations dashboard now separates traffic, response classes, provider
health, circuit state, route traces, request telemetry, endpoint inventory, and
configured cost coverage.

## Rejected

- **Wholesale strategy expansion.** Many auto-routing modes would weaken
  MultiLLM's explicit, debuggable route contract.
- **Synthetic success or fallback bodies.** Provider errors remain errors; the
  proxy does not fabricate a successful model response.
- **Unconditional message or tool rewriting.** A current OmniRoute issue reports
  Codex tool loss when Responses lifecycle fields are stripped. MultiLLM keeps
  provider-specific exceptions and transport fidelity.
- **Single heavy-request admission by default.** A current OmniRoute report shows
  concurrent Codex requests can receive `chat_admission_busy` with the default
  in-flight limit. MultiLLM uses bounded circuit probes instead of a global
  one-request gate.
- **Subscription-cookie and browser-OAuth routing.** MultiLLM remains an API-key
  proxy and does not import browser sessions or bypass provider access controls.
- **Semantic response caching by default.** Paid or user-specific generations are
  not replayed without explicit, protocol-safe cache semantics.

## Sources

- [OmniRoute repository](https://github.com/diegosouzapw/OmniRoute)
- [Latest published release, v3.8.49](https://github.com/diegosouzapw/OmniRoute/releases/tag/v3.8.49)
- [v3.8.50 release branch](https://github.com/diegosouzapw/OmniRoute/tree/release/v3.8.50)
- [OmniRoute quickstart](https://omniroute.online/#quickstart)
- [Auto/combo routing documentation](https://github.com/diegosouzapw/OmniRoute/blob/release/v3.8.49/docs/routing/AUTO-COMBO.md)
- [CLI tools reference](https://github.com/diegosouzapw/OmniRoute/blob/release/v3.8.49/docs/reference/CLI-TOOLS.md)
- [Environment reference](https://github.com/diegosouzapw/OmniRoute/blob/release/v3.8.49/docs/reference/ENVIRONMENT.md)
- [Responses lifecycle tool-loss report, issue 8990](https://github.com/diegosouzapw/OmniRoute/issues/8990)
- [Concurrent heavy-request admission report, issue 9012](https://github.com/diegosouzapw/OmniRoute/issues/9012)
