# Durable usage reservations

Dollar-budgeted keys can retain conservative usage holds after uncertain provider
handoff. The default is `USAGE_RESERVATIONS_ENABLED=false`; existing accounting,
responses, headers, and storage remain unchanged.

Enable with:

```text
USAGE_RESERVATIONS_ENABLED=true
USAGE_HOLD_REVIEW_AFTER_SECONDS=259200
```

An empty value uses the default. Invalid settings disable reservations and emit one
warning per setting, without its value. Review age must be 1–2147483647 seconds.
Review age marks an unresolved hold as `needs_review`; it never releases money.

A reservation moves from `reserved` to `dispatched`, then to `settled` with measured
provider cost or to `unknown` when completion or usage is uncertain. Disconnects after
handoff retain the estimate. Confirmed cancellation before dispatch and cache hits
before dispatch settle at zero with a release basis. A successful response with missing
or partial billable usage retains its hold; missing counters remain null rather than
becoming measured zero. Requests without a configured monetary budget are unchanged.

Admission and settlement use atomic storage transactions. All unresolved holds count
against both current UTC budget periods, even when created in an older period.
Settled charges belong to their admission day and month. Settlement and transition
identifiers reject conflicting replays; these identifiers grant no provider retry
permission. An estimate must fit every configured budget. Any unpriced eligible model
refuses admission with HTTP 503 `unpriced_reservation`. A priced request that exceeds
a budget returns HTTP 429 `budget_exceeded`. Holds round upwards and budget caps round downwards. Money is represented in integer units of
USD 0.0000000001 with a maximum representable amount of USD 900719.9254740991.
Measured spend can exceed the estimate; it is recorded without truncation to the budget.

`/v1/usage` includes content-free `budget.reservations` counters: `held_usd`, `reserved`,
`dispatched`, `unknown`, and `needs_review`. `in_flight_usd` includes unresolved durable
holds, and remaining budgets subtract them. Unavailable storage reports unavailable
totals and null remaining budgets, rather than reporting spendable money.

Unknown reservations require explicit reconciliation. A trusted administrator supplies
the reservation ID, current revision, measured cost, a provider evidence reference and
an audit reason. An explicitly authorized adjustment instead uses an adjustment basis
and audit reason. References and reasons are bounded identifiers, not provider response
bodies or free-form content. Concurrent reconciliations use compare-and-swap; one claim
wins and the other returns `reservation_conflict`. Reconciliation preserves previously
observed counters and retains transition history. No public reconciliation endpoint is
provided by the storage module; the caller must verify administrator authorization
before invoking the reconciliation contract. The private handler is not a public API.

SQLite uses the usage database path (`USAGE_DB_PATH`) and initializes additive tables.
Keep this file on durable shared storage for processes using that authority. D1 uses
`INTELLIGENCE_DB` and the additive `0020_usage_reservations.sql` migration. Its private
JSON endpoint is `http://intelligence.internal/v1/reservations`. Container access uses
an injected `D1ReservationStore` transport; it must not fall back to ephemeral SQLite
when D1 is configured. An absent D1 binding, missing tables, or transport failure returns
HTTP 503 `usage_reservations_unavailable` before provider submission. No new binding
or public route is needed. Rehearse and apply the migration before enabling the feature.

Request owners must persist handoff immediately before provider submission and finalize
with classified, measured accounting. Native owners use `createReservationLifecycle`
with verified identity, all eligible prices and initial legacy spend. They supply measured
cost and nullable counters through the existing flat finalization event (or its `usage`
field), plus the classified outcome and cancellation outcome.
Flask owners use `request_accounting.mark_dispatched` before submission; the existing
cancellation observer also records handoff when it binds an upstream response. Failed
finalization retains money, including a crashed reservation still in `reserved` or
`dispatched`. Review these stale records by an explicit unknown transition before
reconciliation; never assume that lack of a completion proves no provider charge.

Before first enabling, drain existing requests and flush the legacy usage ledger across
all replicas. The first reservation snapshots existing spend for each principal and UTC
period once; subsequent charges come from the durable reservation authority, while the
usage ledger continues to report measured costs without charging them again. Use one
authority and consistent settings on every replica. Do not change the flag during
in-flight requests or disable it with unresolved holds. Enabling after mixed legacy and
durable writers requires an operator-led reconciliation of the baseline. Automatic
external invoice matching, payments, and PostgreSQL reservation storage are not provided.

Hold and audit records contain no prompts, responses, credentials or provider bodies.
They are retained without automatic expiry or deletion, including after review age.
Their storage must be monitored and backed up. This accounting does not establish that
a provider invoice matches local prices, token estimates, or reported metering.
