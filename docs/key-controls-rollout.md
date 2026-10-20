# Key controls rollout

The main Worker, its Container and the private Knowledge Worker deploy independently.
Workers Builds deploys the main Worker and Container without running the GitHub deploy
workflow that deploys the private Knowledge Worker. Do not rely on deployment order.

## Expand

Apply migrations 0041–0043, then deploy the expansion revision to all three components.
Their readiness responses advertise `key_controls: {protocol: 1, enforcement: false}`.
The main Worker also exposes the Container readiness result separately. Verify each
component before proceeding; a build tag alone does not prove the running capability.

Existing accounts have NULL policy columns and retain their existing behavior. The
expansion accepts additive RPC fields and both account row shapes, sends the legacy
protocol, and does not expose setters for restrictions. Legacy account writes preserve
both policy columns in the same SQL statement, including concurrent writes.

If a later revision enables an account restriction, rolling back to this revision
refuses provider dispatch with 503 before sending content. This dormant fence includes
native routes, private bindings, Knowledge, Realtime and deferred work. A malformed or
unreadable current policy cannot grant dispatch. Legacy background jobs without an
identity run only while a fresh durable read proves every policy is NULL.

## Contract

Deploy the enforcement revision only after all three components advertise expansion
support. Verify enforcement capability on every component before enabling restrictions.
Controlled delegation requires a fresh enforcement-capability response from the actual
peer before any content is sent. Unrestricted traffic remains compatible with expansion
peers during independent deployments. Keep deployment preflight enabled.

Rollback from enforcement to expansion leaves policy columns intact and refuses
controlled accounts. Restore enforcement-capable components to resume those accounts;
never clear restrictions as an automatic rollback step.
