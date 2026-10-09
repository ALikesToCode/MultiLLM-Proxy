# Organisations and teams

`ORGANISATIONS_ENABLED` is off by default. Empty values mean off. Malformed values
mean off and produce one warning without the value. With the feature off, the
organisation and workspace endpoints return JSON 404 with `Cache-Control: no-store`
before authentication, CSRF checks or JSON parsing. Existing accounts, key records,
provider traffic and storage formats remain unchanged. Every principal has the
legacy tenant context and an empty namespace.

Enable with `ORGANISATIONS_ENABLED=true` only after applying
`intelligence-migrations/0033_tenant_hierarchy.sql` to the configured account SQLite
database, or to D1 when `INTELLIGENCE_STORAGE_BACKEND=d1`. Missing tables or columns
return JSON 503 `tenant_storage_unavailable`, including for accounts without a
binding. There is no storage fallback or automatic account migration.

The hierarchy has exactly two levels: organisation and team. IDs are generated,
opaque and immutable. Names may have up to 200 characters. Status is `active` or
`deactivated`. Each organisation retains at most 100 teams and 1,000 memberships,
including deactivated rows. The limit returns 409 `tenant_limit_reached`.
Membership roles are `admin`, `billing` and `member`; these labels do not grant
access to the gateway administrator dashboard. Each membership links an existing
account to one organisation and optionally one team in that organisation.

## Administration

The existing administrator dashboard session and CSRF token protect these routes:

- `GET /admin/organisations` lists organisations; `POST` creates one with
  `{"name":"Example"}` and returns 201.
- `GET /admin/organisations/<org_id>` reads one; `PATCH` changes its name or status.
- `GET /admin/organisations/<org_id>/teams` lists teams; `POST` creates one with a name.
- `PATCH /admin/organisations/<org_id>/teams/<team_id>` changes a team's name or status.
- `GET /admin/organisations/<org_id>/members` lists memberships.
- `PUT /admin/organisations/<org_id>/members/<principal>` sets role, team and status.

All updates require `If-Match: "<revision>"`. A new membership requires `"0"`;
existing resources start at revision 1. Missing revisions return 428
`revision_required`; malformed revisions return 400 `invalid_revision`; stale
revisions return 412 `revision_conflict`. Resource and binding responses expose
`ETag: "<revision>"`. Each successful update increments the revision. Team creation
does not change its parent organisation's revision.

For example, to grant a team membership and explicitly select it for that account,
PUT a membership with `If-Match: "0"` and this body, using IDs returned by creation:

```json
{"role":"member","team_id":"<team_id>","status":"active","bind":true,"binding_revision":0}
```

`binding_revision` is the account's current binding revision (zero when unbound).
The membership, binding and audit rows commit together. A stale binding revision
leaves both old records intact. Set `status` to `deactivated` to revoke access;
rows and IDs remain stored. There is no deletion endpoint. Every successful
mutation records actor, action, target IDs, old/new revisions and UTC time. Audit
records exclude names, request bodies, keys and provider content.

## Workspaces

`GET /v1/workspaces` uses a gateway key with the `models` scope and returns only
its active memberships plus its current binding. Administrators also hold this
scope. Unbound accounts have binding revision zero and remain in the legacy
namespace even when they have memberships.

`POST /v1/workspaces/switch` uses the same key and scope, requires
`If-Match: "<binding_revision>"`, and accepts exactly
`{"org_id":"<org_id>","team_id":"<team_id>"}`. Use `null` for an organisation-only
membership. The caller can select only its own active membership and its exact
team. The stored binding applies to the next request; existing request contexts
are unchanged. Dashboard CSRF applies to admin mutations; gateway-key workspace
selection uses the existing API CSRF exemption.

Knowledge and Realtime resolve the workspace only after verifying the credential
for one principal. Accounts sharing a key prefix do not resolve each other's
workspaces. Their authenticated principals carry the validated `tenant_context`;
with organisations off, resolution returns the legacy context without querying
tenant storage.

Resolution uses server storage and ignores `X-Org`, `X-Team`,
`X-MultiLLM-Workspace` and tenant fields in provider request bodies. A missing or
foreign organisation/team is 404 `workspace_not_found`; a deactivated
organisation/team, revoked membership or mismatched membership team is 403
`workspace_forbidden`. A rejected binding prevents provider dispatch and later
policy, cache, claim and admission hooks. An administrator can repair a revoked
binding through the members endpoint. No automatic reparenting takes place.

Python consumers use `current_tenant()` and `tenant_namespace()` from
`services.tenant_hierarchy`; native consumers use the validated `TenantContext`
from the tenant resolver. Namespaces are `org:<id>` or `org:<id>/team:<id>`; the
legacy namespace is the empty string. Resolution rereads authoritative revisions
every request and has no process-local tenant cache.

## Operational limits

The private D1 domain is POST-only at
`http://intelligence.internal/v1/managed-state/tenants`, with a maximum request
size of 8,192 bytes. Writes use conditional SQL and an atomic batch with their
audit rows. Private Flask calls have bounded concurrency and wall time and never
replay an uncertain write. Standalone SQLite uses the configured account database
and serializes writes with an immediate transaction.

Workspace identity does not introduce quotas, credits, payment collection, cost
allocation or provider discounts. Cache, idempotency, hosted-state, context-page
and usage owners include the verified namespace when it is non-empty, isolating records
between workspaces. With organisations disabled, their ownership formats remain
byte-identical to the legacy formats. Existing record ownership never moves
because an account selects a workspace. Audit and hierarchy rows are retained
indefinitely; content-retention policies do not erase them. Deactivation keeps
rows and continues to count toward the caps. There are no live-provider capability
or metering guarantees from these APIs.

The application registers the tenant authority and active membership-role reader
for enterprise identity, payment permissions and governance collaborators.
