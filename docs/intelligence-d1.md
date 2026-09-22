# Intelligence persistence on Cloudflare D1

The `INTELLIGENCE_DB` Worker binding stores intelligence policy, allowance
reservations and integration credential hashes outside the ephemeral Container.
The configured database is `multillm-intelligence`; its additive schema is in
`intelligence-migrations/`.

## Deployment

Apply the schema before deploying the Worker and Container:

```sh
node node_modules/wrangler/bin/wrangler.js d1 migrations apply multillm-intelligence --remote
npm run cf:dry-run
```

The binding automatically sets `INTELLIGENCE_STORAGE_BACKEND=d1` inside the
Container. Do not set that variable on a standalone host: the private domain only
exists inside the configured Cloudflare Container network. Without the binding,
the existing SQLite/PostgreSQL configuration remains in effect, including the
Container requirement for durable intelligence storage.

`INTELLIGENCE_POLICY_JSON` can seed a reviewed policy into an empty D1 table.
First insertion wins; subsequent restarts and competing seeds do not replace it.
An unseeded installation stays disabled. Validate the policy offline first:

```sh
python scripts/intelligence_policy.py validate /private/reviewed-policy.json
```

The `seed` command uses the selected backend. With D1 selected, it must run in the
Container's private network; it cannot reach D1 from an ordinary local terminal.
Review model entitlement, privacy, capabilities and bounded allowances before
setting the deployment seed. No model/provider credentials are stored in D1.

## Private storage boundary

Python sends bounded JSON to `http://intelligence.internal/v1/store` or `/v1/auth`.
`MultiLLMProxyContainer.outboundByHost` directs that hostname to a Worker handler;
the exported `ContainerProxy` entrypoint supplies the Worker bindings. The
Container receives neither a Cloudflare API token nor a database credential.

These paths are not public HTTP administration endpoints. Public requests remain
on the normal application routing path. The private handlers accept fixed domain
operations, never caller-supplied SQL, URLs, clock values or quota ceilings.
Transport permits no redirects, environment proxies or retries and limits each
caller to five seconds. Uncertain submissions must not be replayed automatically.

Reservations use a single conditional insertion against the stored policy and
rolling principal/global allowances. Inflight limits apply per operation kind.
Chat reserves tokens; each configured media operation reserves one request.
Pending and unknown usage remains charged beyond the daily window and across
restarts. Settlement is single-use and keeps a reported overrun. Repeated terminal
reservation IDs cannot authorize more work.

## Integration credentials

Integration keys use the reserved `mllm_intelligence_` namespace and a 32–128
character URL-safe suffix. Their principals use IDs such as `integration:omni`.
Allowed scopes are `chat`, `models`, `audio` and `embeddings`; none grants admin.

Provisioning is an explicit operator operation through the private auth domain,
not an environment seed. Its version-one operation fields are:

| Operation | Fields besides `version` and `operation` |
| --- | --- |
| `provision` | `principalId`, `keyPrefix`, `keyHash`, `scopes` |
| `rotate` | `principalId`, `expectedVersion`, `keyPrefix`, `keyHash` |
| `revoke` | `principalId`, `expectedVersion` |
| `lookup` | `keyPrefix` |

The prefix is the namespace plus the first 16 suffix characters. Supply only a
Werkzeug `scrypt:32768:8:1` hash to this domain; never send it the raw credential.
Keep the raw credential in the consuming service's secret manager. Provision
returns HTTP 201 and credential version 1. Rotation requires the current version;
old prefixes remain reserved. A revoked principal cannot be provisioned again.
Resolve a lost management response by inspecting durable state before proceeding.

Every reserved-key authentication reads D1. Revocation is not hidden behind a
process cache, and storage failure never enables a local-user fallback. Existing
administrator and ordinary user authentication retains its current behavior.
The dashboard's local user-management commands cannot modify these principals.

Integration access is restricted to model discovery and the intelligence chat and
media endpoints. Unified chat must select `auto:intelligence` or include a `routing`
field so it enters the intelligence dispatcher. Legacy provider passthrough,
optimizer, image generation and administrative routes are denied, even when their
ordinary scope name matches. This keeps every integration inference inside the
reviewed policy and durable allowance boundary.

## Scope and recovery

D1 here does not migrate existing dashboard users, model overrides, automatic
routes or generic rate-limit records. Use PostgreSQL control-plane persistence
for those records when needed. The existing encrypted control-plane backup tool
does not include D1; use Cloudflare's D1 recovery facilities separately. Treat
credential hashes and account metadata as private backup data.

Local tests exercise D1 transactions, concurrent replicas, restart persistence
and the private HTTP protocol. A build or local test does not establish that a
deployed Container can reach its handler or that a model account is enabled.
Verify those paths after deployment before selecting this gateway in Omni.

The existing `cloudflare-worker.mjs` remains over 2,000 lines. This integration
adds only binding and handler registration there; persistence and credentials
live in separate modules. A follow-up can extract Container lifecycle and public
request routing independently, without moving the D1 domain logic.
