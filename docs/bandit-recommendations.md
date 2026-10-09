# Bandit route-order recommendations

`BANDIT_MODE` defaults to `off`. An empty value also means off. An invalid value
means off and emits one warning without including the value. In this mode,
existing evaluation proposals and request dispatch keep their existing behavior.

Set `BANDIT_MODE=shadow` to inspect a hypothetical order, or
`BANDIT_MODE=recommendation` to review an order proposal. Both modes read existing
evaluation results. They do not call providers, duplicate requests, explore paid
candidates, change task scores, or apply route configuration. No remote classifier
is used. The administrator session and existing CSRF protection are required.

## Request a proposal

Enable `CONFIG_SNAPSHOTS_ENABLED=true` and configure the existing private D1
snapshot storage. Submit an administrator request with its session CSRF token:

```http
POST /admin/workbench/shadow/propose
Content-Type: application/json

{"route_id":"auto:chat","task_type":"chat","seed":17}
```

Task types are `chat`, `coding`, `extraction`, `writing`, and `reasoning`. The
optional seed defaults to zero and accepts integers from zero to 4294967295.
The response includes `mode`, `route_id`, `task_type`, `seed`, `base_revision`,
`eligible_order_before`, `eligible_order_after`, `evidence`, and `uncertainty`.
Evidence shows sample counts, decayed sample counts, quality and price coverage,
feedback counts, quality estimates, measured average costs, and 95% intervals.
The result is deterministic for the same observations, evaluation time and seed.

A proposal can swap one adjacent pair at most. It retains exactly the configured
candidate IDs and introduces no models, tiers, credentials, or permissions.
The configured order is the review universe; request-time capability, health,
authorization and budget checks still determine which candidates may dispatch.
An unchanged order reports `insufficient_evidence` or `confidence_overlap`.

## Evidence and uncertainty

Each task/model cell needs at least 50 distinct stored samples and complete known
quality and cost coverage. Unknown values remain unknown, including malformed
prices and failed or truncated judgments. A known monetary zero is accepted only
as a measured value. Duplicate exports cannot increase sample counts. Invalid
tool judgments do not support a move. When three-arm evidence is present, its
existing confidence and noise-floor gate must pass, even if three-arm evaluation
is currently disabled.

Observations decay with a seven-day half-life. Decayed quality successes and
failures update a Beta(1,1) prior; 1000 seeded posterior draws supply the 95%
quality interval. Utility is quality minus the weighted mean of
`cost_usd / (1 + cost_usd)`. Empirical cost-penalty variation widens its interval.
A move requires the promoted cell's lower utility bound to exceed the preceding
cell's upper bound. Old evidence therefore has less influence and more
uncertainty. These intervals describe the measured cohort and chosen utility;
they do not certify future quality or remove evaluation bias.

The process holds at most 1000 task/model cells and 10000 observations, rebuilt
from the existing versioned evaluation result store. Results older than 90 days
are excluded. A purge removes their aggregate influence on the next read. Only
identifiers, timestamps, numeric judgments and costs are consumed; prompts,
answers and judge explanations are neither read for scoring nor logged.

## Explicit feedback

An administrator can obtain a nonce for a stored sample/model observation:

```http
POST /admin/workbench/shadow/bandit/nonce
Content-Type: application/json

{"sample_id":"00000000000000000000000000000001","model":"openai:example"}
```

Submit the returned nonce once with a numeric quality from zero to one:

```http
POST /admin/workbench/shadow/bandit/feedback
Content-Type: application/json

{"nonce":"<returned nonce>","quality":1}
```

The nonce binds the stored observation and authenticated administrator. It
expires after 15 minutes. Feedback replaces that observation's quality without
increasing its sample count or supplying a missing price. A second review,
replayed nonce, foreign administrator, expired nonce, or removed observation is
rejected. At most 1000 outstanding nonces are kept. Nonces and explicit feedback
are process-local and disappear on restart; submit to the same running process.
No distributed or durable feedback guarantee is provided. Feedback does not
override a failed tool or noise-floor gate.

## Review and apply

Review the complete proposal, then create a configuration snapshot through
`POST /admin/config/snapshots` using `domain: "auto_routes"`, the proposal's
`base_revision`, and a `configuration.routes` entry containing its `route_id` and
`eligible_order_after`. Review `GET /admin/config/snapshots/{id}/diff`, then use
`POST /admin/config/snapshots/{id}/apply` with `confirm: true` and
`current_revision` equal to the reviewed base revision. This existing apply
path owns the atomic compare-and-swap check and audit record. A stale revision
returns HTTP 409. A proposal is advice; it is never an apply authorization.

While either bandit mode is enabled, `/admin/workbench/shadow/apply` returns
HTTP 400 and directs the operator to snapshot review. A route read checks the
durable revision before and after reading fresh route bytes; a concurrent change
returns HTTP 409. Missing or invalid durable storage fails closed with HTTP 503;
disabled snapshot storage or an absent route returns HTTP 404. Invalid proposal
or feedback fields return HTTP 400. Feedback conflicts return HTTP 409, and the
nonce/feedback endpoints return HTTP 404 while bandit mode is off.

Both direct Flask requests and administrator requests forwarded by the Worker
use these same endpoints. No additional Worker dispatch implementation, storage
migration, browser-readable response header, or provider capability is required.
