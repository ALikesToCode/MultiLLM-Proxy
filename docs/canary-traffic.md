# Canary traffic for auto routes

`CANARY_TRAFFIC_ENABLED` defaults to `false`. An empty value also disables it.
Malformed values disable it and produce one warning without logging the value.
Each route defaults to `{"enabled": false}`. Explicit provider models and routes
without an enabled canary policy keep their existing dispatch and response headers.

An administrator saves the candidate chain and its canary policy together through
the existing authenticated `PUT /admin/auto-routes` endpoint. For example:

```json
{
  "route_id": "auto:experiment",
  "candidates": ["openai:baseline", "openai:candidate"],
  "canary": {
    "enabled": true,
    "mode": "shadow",
    "weights": {"baseline": 90, "candidate": 10},
    "salt_revision": "r1",
    "approved_candidates": ["openai:candidate"]
  }
}
```

With `CANARY_TRAFFIC_ENABLED=true`, shadow mode assigns a proposed cohort and
records its proposed order. It sends exactly the baseline request; it makes no
comparison or additional provider call. Change `mode` to `live` in a reviewed save
to use the proposed order for candidate sessions. Approved candidates move ahead
of the other candidates, preserving the configured order within each group.
Health ordering and per-candidate permission, budget, credential, cooldown and
deadline checks run afterwards and retain precedence. The existing refusal and
stream failover rules still apply. Assignment does not grant retry permission.

Weights must be non-negative integers summing to 100. Approved candidates must
be distinct models already in this route. A nonzero enabled candidate weight
requires an approved candidate. The salt revision is a nonempty identifier of
at most 128 letters, digits, dots, underscores or hyphens, starting with a letter
or digit. Missing optional fields use shadow mode, 100/0 weights, revision `1`
and no approved candidates. Invalid configuration returns HTTP 400 before saving.
Weights never change automatically.

For local storage, include `expected_updated_at` from the route read to reject
a concurrent edit with HTTP 409. Durable saves require `current_revision` when
configuration snapshots or revision sync are enabled; stale revisions return
409. Candidate order, policy and the durable revision commit atomically. Any
durable save failure returns 503 rather than retaining an unconfirmed local copy.
A save omitting `canary` resets the route to its disabled default. To disable an
experiment explicitly, save its chain with `"canary": {"enabled": false}`.
Clearing the global flag disables routing changes without changing saved policy.

Cohorts use HMAC-SHA256 with the existing server-side `JWT_SECRET`. The input is
compact UTF-8 JSON containing the format label `multillm-canary-v1`, the verified
principal, session identifier, route ID and salt revision. The principal is the
compact JSON pair `[tenant_id, id-or-username]` from authenticated request state.
The first four digest bytes, interpreted as an unsigned big-endian integer modulo
100, select baseline below its weight and candidate otherwise. Changing weights,
salt revision, identity or the server secret can reassign sessions.

Session lookup follows prompt cache affinity: `X-OpenCode-Session`, `Session-Id`,
`Thread-Id`, body `session_id`, body `conversation_id`, metadata `session_id`,
metadata `conversation_id`, then the signed authenticated session ID. Without a
session or verified principal the cohort is baseline. A caller-supplied principal
or cohort is ignored. An unavailable assignment secret gives baseline routing and
one warning. A session identifier is an affinity hint, not an authorization grant.

Responses from enabled routes carry the browser-readable
`X-MultiLLM-Canary-Cohort: candidate; mode=shadow` header (or `baseline` and `live`
as appropriate). Cohort identifies an assignment, not which provider won after
the existing filters and fallback. The auto-selected-model header remains authoritative.

The additive `0025_canary_traffic.sql` migration stores only reviewed route policy
and the matching route update timestamp in `canary_traffic`. Apply it before
enabling durable routing. A missing table, failed read or invalid stored policy
falls back to baseline with one warning and does not cause a generation 500.
An older policy never applies to a newly saved candidate chain. Local storage
creates this table only during an explicit canary save; ordinary saves do not.

Request observations contain route, cohort, mode, proposed order and health-ordered
candidate order; candidates rejected during validation are removed from the latter.
Unattempted candidates still need their normal validation if reached. Aggregate
cohort counts retain only route/cohort/mode/count, with at most 800 counters per
process. Counts reset on process restart and measure requests, not unique sessions.
Native Worker dispatch supplies verified identity through `authenticatedPrincipal`
and `sessionIdentifier`, applies `prepareCanary` before eligibility, and observes
the resulting order through its request lifecycle. Forwarded requests use the
Container assignment. Neither runtime stores session plaintext, principal,
HMAC output, prompts, responses or credentials for this feature.

Shadow mode has the baseline request's cost. Live mode can select a more expensive
approved model; existing budgets still apply. Cohort counts do not establish
quality, statistical significance, provider capabilities or exact billing.
