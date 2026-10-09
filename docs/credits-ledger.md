# Gateway credits

Credits are disabled unless `CREDITS_ENABLED=true`. Empty values use the defaults.
`CREDITS_CURRENCY` defaults to USD; other currencies disable credits. Invalid
settings log one warning without their values. Disabled routes return 404.

Apply the additive credits migration to the chosen database before enabling the
feature. It creates `credits_balances`, `credits_entries` and `credits_audit`.
Existing usage records are retained. The runtime does not apply migrations.
Missing tables or required columns return JSON 503 with `credits_unavailable`;
credit admission then stops before provider dispatch. Storage outages have the
same result, without retrying writes or switching to another balance authority.
The local store uses the existing `USAGE_DB_PATH`; the Container uses the private
D1 transport when `INTELLIGENCE_STORAGE_BACKEND=d1`.

Amounts are integer micro-USD, bounded to ±1,000,000,000,000,000. One USD is
1,000,000 micro-USD. Fractional amounts, booleans and overflow are rejected,
without rounding or conversion from usage estimates. Revisions have the same
nonnegative bound. No account receives automatic credit, bonus or top-up.

The ledger stores `credit`, `reserve`, `commit`, `release`, `adjust` and
`compensate` events. Only the materialized balance row changes. Balance is the
sum of credits and adjustments, minus committed costs, plus compensations.
Held credit is the sum of open estimates; available credit is balance minus
held. Every write checks the balance revision. New reservations and negative
adjustments must not make available credit negative. Each owner has its own
operation ID namespace. Repeating an identical
operation, including its original revision, returns its original entry. Reusing
the ID with different content returns 409 `credits_conflict`.

Use a distinct `scoped_id` for each provider attempt, including hedges, shadows
and batch items, and a distinct operation ID for each transition. Reserving an
estimate holds credit. Committing the actual integer cost removes that attempt's
whole hold and debits only the actual cost. The commit entry's `held_delta`
records the released hold atomically. An explicit release removes a hold without
a charge; its amount must match the original estimate. Terminal attempts cannot
reopen.

A commit records the actual cost even when it exceeds the hold and available
credit, and closes only its own hold. Balance and available credit can become
negative within the integer bounds. New reservations are refused while available
credit is zero or negative, until credits or positive adjustments cover the
shortfall and leave available credit for admission.

Unknown reconciliation appends a linked reserve marker with zero balance and
hold deltas. Its zero amount is a marker, not a zero-cost settlement. The original
hold remains indefinitely; there is no automatic expiry. A later known cost can
settle it. A compensation references an original credit, adjustment or commit
operation and applies the exact inverse balance delta once. It never edits the
original entry, reopens a hold or modifies a usage receipt.

Gateway prices are an explicit operator tariff, separate from provider usage
estimates and invoices. `register_credit_authority(store, tariff=...)` and
`registerCreditAuthority(db, {tariff, env})` implement the enterprise
`CreditAuthority` contract. The tariff callback receives `(operation, phase)`;
it must verify the operation's integer amount against the reviewed tariff and
return that tariff's integer revision. Return `None`/`null` for unpriced admission
or unknown reconciliation. Unpriced reserve or commit raises `AuthorityDenied`
with `credits_unpriced`; insufficient funds raise `credits_insufficient`.
Registration performs no storage writes. The authority also checks the feature
flag before evaluating prices or touching storage.

For every authority transition, `AuthorityOperation.revision` must be the owner's
current balance revision. On 412 `credits_revision_mismatch`, re-read that revision
and retry with the same operation ID and unchanged cost and attempt fields, using
a bounded retry limit. A rejected revision writes nothing, and operation IDs make
retries idempotent. After a successful write, replay the original revision to
retrieve its entry; reusing the ID with changed content is a conflict.

`GET /v1/credits` requires a gateway key with `models` scope. It reads only the
authenticated owner; query parameters cannot choose another owner. Verified
tenant context produces a stable organisation/team/principal namespace;
legacy principals keep their existing namespace. The response is:

```text
{currency: "USD", balance_microusd: 100, held_microusd: 60,
 available_microusd: 40, entries: [...], next_cursor: null}
```

Use `?limit=20&cursor=0` for pagination. The limit is 1–100 (default 100); cursors
are nonnegative revision strings. Follow `next_cursor` until it is null. Pages
are ordered by increasing ledger revision. All responses use `Cache-Control:
no-store`. Reads and writes include an `ETag` containing the balance revision.
Entries contain operation IDs, integer deltas, attempt/reference IDs and tariff
revisions. They omit actor and adjustment reason. No prompts, completions,
provider credentials or payment details are collected.

`GET /admin/credits/<owner>` requires an administrator dashboard session and
includes the current revision. URL-encode tenant owner IDs.
`POST /admin/credits/adjust` requires the same session, a CSRF token and an
`If-Match` header copied from the owner's current ETag. For example:

```text
If-Match: "0"
X-CSRFToken: <dashboard CSRF token>
{"owner":"alice","amount_microusd":1000000,
 "operation_id":"allocation-1","reason":"Reviewed allocation"}
```

Missing `If-Match` returns 428 `credits_revision_required`; a stale revision
returns 412 `credits_revision_mismatch`. Negative adjustments are allowed only
within available credit. Reasons must be 1–512 printable ASCII characters.
Audit rows atomically record owner, operation ID, revision, actor and kind, with
no reason or request content. Treat reason text as administrative metadata and
keep user content out of it. Ledger and audit history are retained; this feature
provides no deletion, automatic payment, currency conversion or invoice service.

Application integration uses `register_credits_routes(app, csrf)` in
`app.py:create_app`. Bind verified context as `g.tenant_context`. Supply the
registered credit authority to `services/enterprise_contract.py:
register_enterprise_adapters`, preserving the other authority collaborators.
Reservation integration calls reserve from `services/budget_service.py:
BudgetService._reserve_durable` / `services/request_accounting.py:begin`, commit
from `BudgetService.complete` / `services/request_accounting.py:_record_budget`,
and reconcile from `services/reservation_store.py:reconcile`. Use independent
attempt identities and the current balance revision. The private dispatcher call site is
`worker/managed-state-dispatch.mjs:handleManagedStateRequest`, mapped to
`handleCreditsRequest` for `/v1/managed-state/credits`. The Container transport
uses the `credits` domain, allowlisted as `/v1/managed-state/credits` in
`services/intelligence_d1_store.py:_ENDPOINTS` on the private internal origin.
For native requests, bind the authority at the reserve/settle/reconcile call
sites in `worker/reservations-d1.mjs:createReservationLifecycle` through the
fixed registration in `worker/gateway-extensions.mjs`. These call sites must
classify unknown costs rather than translating them to zero. `CreditDenied`
extends `AuthorityDenied` with bounded `code` and `status`; Flask route
registration installs its JSON error handler. Native request integration uses
the denial's `response()` method through `generationErrorResponse` so schema
failures remain JSON 503 denials.

Usage receipts may include an optional ledger operation ID and revision as
provenance. Credit admission and settlement do not require receipt storage,
and receipt errors must never trigger a second charge. Local tests exercise
SQLite and a SQLite-backed D1 contract fake; they do not validate deployed D1,
live provider metering or an operator's tariff.

Shared integer and idempotency vectors:

```json
[
 {"invalid_amount": true},
 {"invalid_amount": 0.5},
 {"invalid_amount": 1000000000000001},
 {"invalid_amount": -1000000000000001},
 {"request": {"owner":"alice","kind":"credit","amount_microusd":100,"operation_id":"fund","revision":0},"revision":1},
 {"request": {"owner":"alice","kind":"credit","amount_microusd":100,"operation_id":"fund","revision":0},"revision":1},
 {"request": {"owner":"alice","kind":"credit","amount_microusd":101,"operation_id":"fund","revision":0},"error":"credits_conflict"},
 {"request": {"owner":"alice","kind":"reserve","amount_microusd":60,"operation_id":"hold","revision":1,"scoped_id":"attempt","tariff_revision":1},"revision":2},
 {"request": {"owner":"alice","kind":"reserve","amount_microusd":50,"operation_id":"second","revision":2,"scoped_id":"other","tariff_revision":1},"error":"credits_insufficient"},
 {"request": {"owner":"alice","kind":"commit","amount_microusd":25,"operation_id":"charge","revision":2,"scoped_id":"attempt","tariff_revision":1},"revision":3},
 {"request":{"owner":"overrun","kind":"credit","amount_microusd":100,"operation_id":"fund","revision":0},"revision":1},
 {"request":{"owner":"overrun","kind":"reserve","amount_microusd":60,"operation_id":"hold","revision":1,"scoped_id":"attempt","tariff_revision":1},"revision":2},
 {"request":{"owner":"overrun","kind":"commit","amount_microusd":150,"operation_id":"charge","revision":2,"scoped_id":"attempt","tariff_revision":1},"revision":3,"summary":{"balance_microusd":-50,"held_microusd":0,"available_microusd":-50}},
 {"request":{"owner":"overrun","kind":"reserve","amount_microusd":1,"operation_id":"denied","revision":3,"scoped_id":"next","tariff_revision":1},"error":"credits_insufficient"},
 {"request":{"owner":"overrun","kind":"credit","amount_microusd":100,"operation_id":"refill","revision":3},"revision":4,"summary":{"balance_microusd":50,"held_microusd":0,"available_microusd":50}},
 {"request":{"owner":"overrun","kind":"reserve","amount_microusd":1,"operation_id":"next","revision":4,"scoped_id":"next","tariff_revision":1},"revision":5,"summary":{"balance_microusd":50,"held_microusd":1,"available_microusd":49}}
]
```
