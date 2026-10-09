# Top-ups and payment billing

Payments create explicit USD top-ups through Stripe Checkout. A browser redirect
has no effect on a balance. Credits come only from signed processor evidence and
the configured credits ledger callback.

## Configuration

Payments are disabled by default. With `PAYMENTS_ENABLED` unset, empty or false,
every `/v1/payments/*` request returns JSON 404 without payment storage or
processor access. A malformed flag or configuration disables payments and emits
one warning without configuration values.

An enabled example uses references to privately configured secrets:

```json
{
  "PAYMENTS_ENABLED": "true",
  "PAYMENT_PROCESSOR_CONFIG_JSON": "{\"processor\":\"stripe\",\"secret_key_ref\":\"STRIPE_MERCHANT_SECRET\",\"return_origins\":[\"https://billing.example.com\"],\"product_name\":\"Gateway credits\"}",
  "PAYMENT_WEBHOOK_KEY_REF": "STRIPE_ENDPOINT_SECRET"
}
```

The merchant key and webhook signing secret are supplied by the host's secret
resolver. Their values never belong in the JSON configuration, responses or
logs. Use a webhook endpoint belonging to the same direct Stripe merchant as
the Checkout key. Connected-account events are rejected. Test and live mode
must match the Checkout Session returned by Stripe.

Payment routes require a migrated durable store. The private D1 domain is
`http://intelligence.internal/v1/managed-state/payments`, with fixed reserve,
save, find, claim and finish operations. `D1PaymentStore` accepts a private
transport; `SqlPaymentStore` accepts an existing migrated SQLite database.
Neither creates tables or falls back to memory. Missing tables, missing
columns, unavailable storage or unconnected storage return JSON 503
`payments_unavailable` before any processor request. Apply the additive payment
migration through the normal migration process before enabling the flag.

## Checkout

Send a gateway key to `POST /v1/payments/checkout` with:

```json
{
  "amount_microusd": 500000,
  "currency": "USD",
  "idempotency_key": "topup-2026-10-09-001",
  "return_url": "https://billing.example.com/return"
}
```

The default permission grants only the verified key owner in the legacy
single-principal scope. Organisation workspaces require the injected permission
authority to verify a billing or admin role and an injected verified tenant
context resolver. Client body fields cannot select a workspace. Gateway key
scope enforcement also applies.

Amounts are integer micro-USD, in whole cents: multiples of 10,000, from 500,000
($0.50) to 1,000,000,000 ($1,000). The currency is exactly `USD`. The return URL
must use HTTPS and match an allowlisted origin, including its port, exactly.
An idempotency key is an opaque 1–128 character identifier using letters,
digits, underscores, colons, periods or hyphens.

At most ten distinct checkout reservations are accepted per principal per UTC
day, including processor failures. Reusing the same scoped idempotency key and
body returns the same checkout without consuming another reservation. Reusing
it with a different body returns 409 `payment_idempotency_conflict`. Concurrent
creation in another process can return retryable 503
`payment_checkout_processing`; retry the same key and body.

The processor request is form encoded, goes only to
`https://api.stripe.com/v1/checkout/sessions`, has redirects disabled and uses
the opaque checkout ID as Stripe's idempotency key and client reference. Its
only metadata is that opaque ID. Processor failures return 503
`payment_processor_unavailable`; retrying preserves the original processor
idempotency ID.

A successful checkout response is:

```json
{
  "checkout_id": "pay_example",
  "url": "https://checkout.stripe.com/c/example",
  "amount_microusd": 500000,
  "currency": "USD",
  "status": "pending"
}
```

Opening the URL allows payment at Stripe. Returning to the browser URL never
credits a balance. The returned `pending` describes the checkout response,
not a confirmed payment.

## Processor evidence and reconciliation

Configure Stripe to deliver these types to `POST /v1/payments/webhook`, and
confirm them in the Stripe dashboard:

- `checkout.session.completed`: credit only with `payment_status=paid`.
- `checkout.session.async_payment_succeeded`: credit the delayed payment.
- `checkout.session.async_payment_failed`: record failure without credit.
- `charge.refunded`: append the increase in cumulative refunded amount.
- `charge.dispute.created`: append a dispute compensation or hold through the
  ledger callback, using the dispute ID as its stable operation identity.

The webhook requires no gateway key and is CSRF-exempt. It reads raw bytes
before parsing JSON, verifies every supported `v1` signature candidate with
HMAC-SHA256 and requires the timestamp to be within 300 seconds in either
direction. Re-serialization invalidates signatures. Unsupported schemes never
authorize an event. Bodies are limited to 65,536 bytes.

Signed events must match the stored session, direct merchant, mode, currency and
amount. Refunds and disputes must link through the payment intent recorded on
verified session evidence. Refund totals cannot exceed the original charge;
disputes cannot exceed the checkout amount. Mismatches and unknown types are
recorded and acknowledged without credit.

Refund or dispute evidence arriving before the session's payment intent is known
is retained as `pending_match` and returns 503 for retry. After the verified
session links the intent, the same event can be reconciled without losing its
original evidence hash or audit history.

An atomic event claim precedes the immutable `PaymentEvent` callback. A
completed replay returns 200 without invoking it again. Both session success
types share one credit operation, cumulative refund notifications apply only
their delta, and repeat dispute IDs share one compensation operation. An event
ID reused with different bytes returns 400 `payment_event_conflict`.

The callback is the only credit authority. It must apply its immutable
idempotency ID atomically, including when recovering from a process crash after
ledger application but before the payment record is finalized. A missing,
denied, failing or unbound callback leaves `pending_credit` evidence and returns
503 `payment_credit_unavailable`, allowing Stripe to retry. Concurrent active
claims also return this error. A claim can be recovered after a 60-second lease;
retry the original event first before processing other events for that checkout.
Do not acknowledge outstanding credit work manually as paid. Ledger history is
never erased by refunds or disputes.

## Errors, retention and billing policy

Invalid checkout input or signature returns 400; absent authentication returns
401; denied billing permission returns 403; disabled payments return 404;
idempotency conflicts return 409; velocity exhaustion returns 429
`payment_velocity_limited`; unavailable processor, permission, storage or credit
authority returns 503. Payment responses use `Cache-Control: no-store` and
contain no secrets. Unknown payment methods return 405 when enabled.

Stored records contain opaque identity and checkout scope, processor IDs,
integer amounts, mode, event/body hashes, claims, revisions and content-free
audit outcomes. Return URLs and raw webhook bodies are not stored. Card data,
customer names and email addresses are not stored. Operational records have no
automatic purge; retain them according to reconciliation policy. Velocity
counters use UTC day partitions and are independent of refund history.

Taxes, invoices, processor fees and charge policies remain explicit operator
settings. The top-up amount is the credit amount; estimated usage is not an
invoice. Rehearse the configured checkout and webhook flow in the merchant
sandbox before accepting live payments.

The fixed processor contract follows the Stripe documentation:
[webhooks](https://docs.stripe.com/webhooks),
[signature verification](https://docs.stripe.com/webhooks/signature),
[Checkout Session creation](https://docs.stripe.com/api/checkout/sessions/create),
[Checkout metadata](https://docs.stripe.com/payments/checkout-sessions), and
[currency units](https://docs.stripe.com/glossary). Verify endpoint event selection in the Stripe dashboard.
