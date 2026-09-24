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

### Subscription credential

The optional Worker secret `INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY` isolates
reviewed NanoGPT `subscription` chat candidates from the general NanoGPT key pool.
The Worker passes it into the Container environment; it is never stored in D1.
Setting a secret publishes a new Worker version, so run this only when ready:

```sh
node node_modules/wrangler/bin/wrangler.js secret put INTELLIGENCE_NANOGPT_SUBSCRIPTION_API_KEY
```

When it is set, those candidates send only this key. It is not probed, rotated or
replaced by a general key, even after a rejection or rate limit; availability
fallback moves to the next reviewed candidate within the policy's attempt limit.
Other billing modes, other providers, non-subscription media and general proxy
traffic keep their current credentials; subscription media is still refused before
sending. Without the secret, subscription candidates keep using the general pool.
An explicitly empty secret refuses dispatch instead of selecting a general key.

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
Allowed scopes are `chat`, `models`, `audio`, `embeddings`, `knowledge:read` and
`knowledge:manage`; none grants admin.

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
The edge Worker authenticates these keys for Knowledge MCP and REST requests
itself. It still reads the current D1 row on every request and memoizes only the
scrypt comparison against that row's hash, so rotation and revocation apply at once.
The dashboard's local user-management commands cannot modify these principals.

Integration access is restricted to model discovery, the intelligence chat and
media endpoints, and the Knowledge routes (`/mcp` and `/v1/knowledge/*`), which
require `knowledge:read` or `knowledge:manage`. Unified chat must select `auto:intelligence` or include a `routing`
field so it enters the intelligence dispatcher. Legacy provider passthrough,
optimizer, image generation and administrative routes are denied, even when their
ordinary scope name matches. This keeps every integration inference inside the
reviewed policy and durable allowance boundary.

### Operator CLI

`scripts/intelligence_operator.mjs` runs the Worker's own store and auth handlers
in the operator's process against the remote D1 binding from Wrangler's
`getPlatformProxy`, using the existing Wrangler login. It exposes no endpoint and
accepts no SQL, policy JSON or credential on the command line. Each run writes a
temporary configuration containing only `INTELLIGENCE_DB` (`remote: true`), loads
no `.env` or `.dev.vars`, persists no local state and removes the configuration.

```sh
node scripts/intelligence_operator.mjs status --account-id <account> --database-id <database_id>
node scripts/intelligence_operator.mjs seed --account-id <account> --database-id <database_id> \
  --policy-file /private/reviewed-policy.json
node scripts/intelligence_operator.mjs provision --account-id <account> --database-id <database_id> \
  --principal integration:omni --scopes chat,models --credential-file /private/omni.key
```

`seed` and `provision` are dry runs until `--apply` is added; dry runs validate
with the domain handlers but make no remote call and create no file. `status`
reports only whether a policy is `unseeded`, `configured` or `invalid`, plus table
row counts. `seed` is insert-only: `inserted: false` means the stored policy was
kept. The Worker checks only ledger limits, so validate the file with the Python
command above first.

`provision` generates the key in memory and saves it to a new owner-only (`0600`)
file before sending only its prefix and scrypt hash. Existing paths and links are
refused. Output is one sanitized JSON line without keys, hashes, prefixes or policy
values. Exit status 0 means success, 1 a refusal or failure that changed nothing
remotely, 2 a usage error and 3 an uncertain outcome. After an uncertain outcome
the saved key is retained and nothing is retried: run `status` and inspect durable
state first. A conflict means the principal already exists or was revoked. This
CLI does not rotate or revoke credentials.

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
