# Revision-aware live configuration sync

Configuration revisions are committed counters, not a push consistency guarantee. The
feature is off by default. Disabled startup does not register a poller or a freshness
guard, and existing reads, saves and upstream catalog refresh timing stay unchanged.
No disabled operation reads or writes `control_revisions`.

```text
CONFIG_REVISION_SYNC_ENABLED=false
```

Apply migration `0017_control_revisions.sql` through the separately approved migration
process, after the config snapshot and usage bucket migrations (`0015` and `0016`). A
code deploy does not apply D1 migrations. Enable on the Worker and its Containers:

```text
CONFIG_REVISION_SYNC_ENABLED=true
CONFIG_SYNC_TTL_SECONDS=30
CONFIG_SECURITY_TTL_SECONDS=5
INTELLIGENCE_STORAGE_BACKEND=d1
AUTH_STORAGE_BACKEND=d1
```

Flask sync requires Container D1 control and account storage. Standalone SQL/SQLite
mode and unsupported storage combinations disable the feature and log one warning,
without changing existing authentication. This does not fall back from an unavailable
D1 authority: configured D1 with a missing migration or an outage still fails closed.
Storage selection is a startup setting; restart Containers after changing it.

Empty values mean defaults. Malformed settings disable sync and log the variable name
once, without its value. Ordinary TTL accepts 1–3600 seconds. Security TTL accepts
1–5 seconds; a longer value cannot extend the security safety bound.

The existing control-state scheduler polls revisions with an interval between 80% and
100% of the TTL. Each consumer permits one poll at a time and failures keep the same
bounded schedule. A revision check costs one private D1 call per due group. Changed
domains additionally load their stored copy and verify the revision again. Revisions
that decrease, failed loads, and writes racing a load cannot certify freshness. A copy
loads at startup and thereafter only when a newer committed revision is observed.
Scheduler delay and authority latency can cause a temporary fail-closed response.

`GET /admin/config/revisions` requires a dashboard administrator when enabled and is
404 when disabled. It returns only domain names, revision numbers, age, stale flags,
security classification and the time until the next poll. It contains no keys, model
lists, prompts, responses or provider payloads. Ordinary auto routes and provider
catalogs retain the last installed copy during an outage and report `stale: true`.
Before the first route load, seeded routes remain available. New processes cannot
recover an ordinary last-good copy while its authority is unavailable.

API and MCP dispatch fails with HTTP 503 and `config_security_stale` while security
metadata has never been verified, a newer security revision cannot be installed, or
the last verification is older than the security TTL. Admin recovery and status remain
accessible; preflight does not dispatch. Enabled revision operations with a missing
table return a content-free JSON 503. There is no automatic policy change, inference
retry, or success response substituted for a failure.

## Committed domains

`auto_routes` retains the config snapshots counter in `config_snapshot_revisions`; it
has no second row in `control_revisions`. The private auto-route wrapper reuses atomic
snapshot saves for normal writes without enabling snapshot APIs. Snapshot apply
retains CAS and bumps exactly once. Model overrides and provider catalog writes update
their domain counter in the same D1 transaction as their data.

Account upserts and deletes atomically increment both `key_controls` and `model_grants`
with the account mutation and its audit record. Upserts replace the full account,
covering revocation, rotation, scopes, model allowlists, budgets, expiry and address
ranges; both counters advance conservatively even for an unchanged replacement or a
missing-account delete. Usage-only touches and refused account writes do not advance
security revisions. With the feature off, existing writes keep their original SQL and
responses, including compatibility reads for older account schemas.

Flask installs strict account refreshers for both security domains by default. Each
reads all account pages from the private D1 authority using the full control schema,
validates the records, clears the verified-key memo, and installs the account and grant
copy. Invalid records or incomplete schemas raise; there is no fallback to missing
controls or cached grants. Authentication uses this installed copy, serialized with
refreshes, so a revoked, deleted or rotated key is rejected after the successful poll
without waiting for the existing 60-second memo TTL. Model grants and scopes come from
the same installed records. Budgets, model allowlists, expiry and address restrictions
remain enforced by their existing request policies. Environment bootstrap admin and
integration-key authentication retain their existing authorities; integration keys are
verified against their private authority on each request.

Both domains currently load the shared account table separately. Each refresh costs
one private call per page of up to 200 accounts plus the group's revision confirmation;
new revisions clear all verified-key memos in that process. Account copies remain in
process memory only. The revision table holds one counter and timestamp per domain,
with no event history or request content. Existing account audit, snapshot history and
catalog retention policies remain unchanged.

## Runtime interfaces

`register_gateway_extensions` mounts the Flask guard and status route. Other middleware
can be supplied as explicit callbacks in policy order; there are no dynamic imports or
plugin discovery. `configure_sync` supplies the model-override and both account/grant
installers automatically. An explicit `security_refreshers` override must load from
its committed authority or raise; an absent installer remains fail closed.

Private auto-route dispatch can call
`handleRevisionedAutoRoutes(request, env, {handleAutoRoutesRequest, boundedBody})` using
its static handler and bounded body reader. Revision persistence has no dependency on
the account or auto-route handler. `commitRevision(db, ["key_controls", "model_grants"],
statements)` accepts trusted fixed D1 statements, never SQL from a request. Its optional
expected revision permits one concurrent CAS winner; a failed CAS rolls back all data,
audit and revision statements.

Native Worker dispatch can supply strict installers to `RevisionConsumer`, invoke
`tick` through its background lifecycle, and call `requireFreshSecurity` before dispatch.
The guard returns a JSON 503 response or null when freshness permits normal dispatch.
Read callbacks return an exact domain-to-integer mapping; installer callbacks throw on
authority failure. The native consumer has no default account/grant installer: a missing
callback is its fail-closed fallback, equivalent to Flask's `missing_security_refresh`
for an explicitly absent installer. Native status can use the content-free `status`
method. Polling does not guarantee immediate cross-region visibility or live deployment
health.
