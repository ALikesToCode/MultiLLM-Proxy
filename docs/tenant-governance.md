# Tenant governance

`TENANT_GOVERNANCE_ENABLED` is off by default. Empty values are off. Invalid values
produce one warning without logging the value and are treated as off. When disabled,
key controls, budgets, routing and usage keep their existing behaviour; the governance
administration endpoints return 404. Legacy principals keep that behaviour when enabled.

The server supplies a verified `TenantContext` through a registered `tenant_resolver`
and an organisation role through `membership_role(principal_id, org_id)`. The default
resolver uses the enterprise legacy authority; the default membership role grants no
permissions. Request headers and JSON fields cannot choose an organisation or role.

## Grants and permissions

The key grant, organisation grant and team grant must all allow a model or tool.
A missing ancestor row or a null grant adds no restriction. An empty array denies
everything at that level. Patterns are case insensitive; `*` matches any characters.
The same model intersection applies to automatic route candidates and model-free
provider calls. A provider call without a model requires a whole-provider grant.

Organisation administrators can edit grants and budgets and read workspace usage.
Billing members can read budgets and workspace usage. Members can read their own
workspace usage. These endpoints cannot edit roles or memberships.

`GET /admin/organisations/<org_id>/governance` and
`GET /admin/organisations/<org_id>/teams/<team_id>/governance` require an administrator
dashboard session and an appropriate organisation membership. Their `PUT` counterparts
also require CSRF and the quoted revision in `If-Match`. Missing revisions return 428;
stale revisions return 412. Responses expose the successor revision as `ETag`.

Example policy body with governance enabled:

```json
{"models":["openai:*"],"tools":["search"],"daily":1000000,"monthly":20000000}
```

Budget values are non-negative integer micro-USD, below 9,007,199,254,740,991.
`PUT` replaces the policy: omitted fields become null. It does not add to a grant.
Audits contain identifiers, revision, operation kind and time, without policy content.

## Monetary reservations and usage

An enabled workspace admission reserves the estimate against the key, organisation
and team together. Daily periods use UTC dates; monthly periods use UTC calendar
months. A zero budget denies admission. Existing key spending seeds its period
baseline. Unpriced requests return 503 `unpriced_reservation`. An ancestor limit
returns 429 `tenant_budget_exceeded` with the rejecting level; a key limit keeps
`budget_exceeded`. Rejected admission creates no reservation or component.

Measured completion settles all components atomically. Unknown cost retains the
conservative estimate at every level, including across period changes; holds do
not expire automatically. Pre-dispatch cancellation can release a reservation.
Settlement is idempotent and cannot replace a settled cost with a different amount.
Actual cost can exceed the admission estimate; configure conservative pricing and
output bounds. Estimates and measured gateway costs are not provider invoices.

`GET /v1/usage` includes `workspace` only for enabled workspace callers. Its history,
model totals and daily totals use that verified workspace, without reading unscoped
legacy history. Members see their own records; administrators and billing members
see workspace totals plus organisation and selected-team totals. Model rows identify
the actual model, provider and price basis. Results have at most 200 model groups
and 90 daily groups. Usage and audits contain no prompts or response content.

Apply `0034_tenant_governance.sql` before enabling governance. The migration creates
only new tables and indexes and can be rehearsed against existing rows. A missing
table, column or unavailable authority returns JSON 503
`tenant_governance_unavailable` before admission. No permissive fallback is used.

The D1 domain is mounted only behind the authenticated private dispatcher at
`http://intelligence.internal/v1/tenant-governance`. Native admission uses
`createGovernanceLifecycle` with verified tenant and key decisions, integer price
estimates, dispatch and finalization hooks. Flask uses the same domain through
`D1GovernanceStore`; `SQLiteGovernanceStore` supports explicitly injected connection
factories and database transactions. Neither adapter applies migrations automatically.
Storage failure prevents new admissions; ambiguous settlement leaves the hold in place.
Retention and any reconciliation of unknown holds require an operator policy.
