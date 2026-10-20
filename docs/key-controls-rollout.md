# Key controls rollout

The main Worker, its Container and the private Knowledge Worker deploy independently.
Workers Builds deploys the main Worker and Container without running the GitHub deploy
workflow that deploys the private Knowledge Worker. Do not rely on deployment order.

## Expand

Apply migrations 0041–0043, then deploy the expansion revision to all three components.
Their readiness responses advertise `key_controls: {protocol: 1, enforcement: false}`.
The main Worker also exposes the Container readiness result separately. Verify each
component before proceeding; a build tag alone does not prove the running capability.

Existing accounts have NULL policy columns and retain their existing behavior. Any non-NULL policy value,
including `official_only=0` or an empty preference object, activates the expansion refusal fence. The
expansion accepts additive RPC fields and both account row shapes, sends the legacy
protocol, and does not expose setters for restrictions. Legacy account writes preserve
both policy columns in the same SQL statement, including concurrent writes.

If a later revision enables an account restriction, rolling back to this revision
refuses provider dispatch with 503 before sending content. This dormant fence includes
native routes, private bindings, Knowledge, Realtime and deferred work. A malformed or
unreadable current policy cannot grant dispatch. Legacy background jobs without an
identity run only while a fresh durable read proves every policy is NULL. Headerless
private calls from a verified expansion Container remain compatible beside controlled
accounts: that Container applies its current-account refusal fence before the hop.
An unreadable or malformed store cannot use this compatibility proof.

## Contract

Deploy the enforcement revision only after all three components advertise expansion
support. Verify enforcement capability on every component before enabling restrictions.
Controlled delegation requires a fresh enforcement-capability response from the actual
peer before any content is sent. Unrestricted traffic remains compatible with expansion
peers during independent deployments. Keep deployment preflight enabled. Expansion
already checks the required secret names, both account tables' policy columns and the
complete migration ledger before main upload; enforcement retains those checks.

Rollback from enforcement to expansion leaves policy columns intact and refuses
controlled accounts. Restore enforcement-capable components to resume those accounts;
never clear restrictions as an automatic rollback step.

## Staging evidence and management compatibility

Real staging of the earlier re-land reproduced both incident errors with mixed Worker
and Container versions. The matched original enforcement release was healthy on 45 of
46 requests. Forward negotiation fixed the new-Worker/old-Container mix, but the reverse
rollback still produced roughly 50–55 seconds of chat 503s in two samples. Treat both
RPC directions as compatibility requirements; a passing matched-version test is insufficient.

The local matrix uses real migrated D1 rows, the account RPC and registered Container
routes. Every A/B combination must keep unrestricted chat and Knowledge working, including
rollback with restricted rows still stored. It also signs in both a controlled account
and an unrestricted administrator, then reloads the complete management account list.
Policy capability checks belong at provider dispatch/delegation, never a management read.
A restricted row must not poison another account's login or dashboard. Management access
does not grant generation authority; A's dispatch fence remains active after sign-in.
These are local compatibility proofs; repeat them on staging before relying on plain rollback.

## Deployment verification

Expansion release admission runs from the default main Worker build and both deployment
entry points. Before private upload, `--prepare` verifies the exact local migration ledger,
`control_users` and `intelligence_principals` policy columns, and the required main binding
names (`ADMIN_API_KEY`, `FLASK_SECRET_KEY`, `JWT_SECRET`), without reading secret values.
Before main upload it also verifies a single fully active private deployment tagged with
an expansion-capable source revision. Keep that revision's history available locally.
These deployment checks are separate from runtime capability probes and the final
Container version/image/fingerprint verification. All remote migration commands require
an explicit database argument or `D1_DATABASE`; there is no production fallback.

Before merging, disconnect Workers Builds or change its deploy command to
`npx wrangler versions upload`, which uploads without promoting traffic. Use
`scripts/deploy.sh` to preserve migrations → private Worker → main Worker → Container.
The preflight's token permissions inside Workers Builds remain untested: they include D1,
secret-list and deployment/version reads, plus Container list/detail for rollout
verification. Do not treat a locally passing preflight as proof that the Builds token
has those permissions.

Set `D1_DATABASE` explicitly, matching `INTELLIGENCE_DB` in both selected configs.
For another environment also set `MAIN_WORKER_CONFIG`, `KNOWLEDGE_WORKER_CONFIG` and
`DEPLOY_STATUS_URL`. Status reads require `--database` or `D1_DATABASE` and validate
that target against both configurations; there is no implicit production database.
Use `--config` and `--knowledge-config` for status against alternate configurations.

Wrangler can print "Image already exists remotely" and "no changes" while leaving an
old Container running, even with immediate rollout. Its application list can lag the
application detail. The deploy script records the detail version/image before upload,
adds a fresh build-only image identifier, and polls the detail after deployment. It
requires a strictly newer version and changed image, plus matching actual Worker and
Container artifact fingerprints on `/ready`. A no-op, unavailable probe or mismatch
fails the deployment after a bounded wait. Never enable controls after such a failure.
The GitHub deployment workflow uses the same capture and verification. These checks are
read-only and do not change secret bindings, D1 data or rollout policy.

Until A/B rollback has passed real staging, use the staging-verified Container-first
rollback: from the newer Worker checkout, deploy a reviewed temporary config referencing
the previous Container image digest (without the Dockerfile build command). Keep the
newer Worker active. Verify that application detail advanced to that image and the
responding Container has the intended previous fingerprint. Only then deploy the previous
Worker with `--containers-rollout=none`. If Wrangler reports no changes, stop and resolve
the image rollout; do not advance to the Worker rollback. Do not disable the normal
preflight for routine deploys; an emergency digest rollback is a separately reviewed
operation. Keep migrations and stored restrictions intact. Once A is installed everywhere,
B→A rollback must retain unrestricted service and refuse controlled dispatch on every path.

Mixed-load "Container suddenly disconnected" failures also occurred on old code
(roughly 9–14% in that staging load). They are outside this rollout change. Zero policy
errors in the compatibility matrix does not claim zero infrastructure disconnects.

See [Container deployment semantics](https://developers.cloudflare.com/containers/guides/deploy/)
and [rollout controls](https://developers.cloudflare.com/containers/configuration/rollouts/).


Account reads negotiate the additive row protocol only after a successful capability probe. Old Containers receive the original account fields on list reads and NULL-policy username reads, including when a controlled neighbour exists, so dashboard cache reloads and unrestricted sign-in remain available. Legacy username and prefix authentication refuse controlled rows, since either can also feed deferred provider work. Provider forwarding and private outbound admission remain separate from management projection; an old Container cannot use a projected row to dispatch for a controlled account. A Containers request the full policy from compatible peers and retain their dormant refusal fence. A failed or malformed capability probe never downgrades to a legacy row; only the old peer's explicit unsupported-operation response permits that fallback.
