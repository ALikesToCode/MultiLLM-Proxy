# Enterprise integration contracts

`ENTERPRISE_PREVIEW_ENABLED` defaults to off. Empty, `false`, `0`, `no` and `off` disable the preview. `true`, `1`, `yes` and `on` enable it, ignoring case and surrounding whitespace. Malformed settings disable it and log one warning per process without the supplied value.

With the default settings, `GET /admin/enterprise/preview` returns HTTP 404, including for unauthenticated requests. To enable it, set `ENTERPRISE_PREVIEW_ENABLED=true` and use an existing administrator dashboard session:

```sh
curl --cookie session-cookie.txt https://gateway.example/admin/enterprise/preview
```

The enabled route returns a JSON descriptor with `version: 1`, `dry_run: true`, `activation: false`, contract names, registered-authority availability and the supported operations. It does not call an authority or mutate grants, quotas or balances. An unauthenticated JSON request returns 401; an authenticated non-administrator returns 403. It sends `Cache-Control: no-store`. There is no Worker-native public preview route; the Flask preview is served through the existing Container transport.

## Authority boundary

Python exports frozen dataclasses and typed protocols from `services/enterprise_contract.py`. Worker exports frozen classes and matching JSDoc interfaces from `worker/enterprise-contract.mjs`. Construct `AuthorityOperation(context, scoped_id, revision, operation_id, amount)` in Python, or pass those named fields to the Worker constructor. A context carries `principal_id`, optional `org_id`/`team_id`, and `grants_revision`; a team requires an organisation.

Identifiers are opaque, case-sensitive ASCII strings of 1–128 letters, digits, underscores, colons, dots or hyphens. They are never parsed as hierarchy, paths or credentials. Revisions and amounts are nonnegative integers below 9007199254740991 so both runtimes agree exactly. Amounts use the registered authority's documented integer units; these contracts introduce no pricing or currency conversion. An authority's successful result must retain the exact context, scoped ID and operation ID, and return the atomic successor revision. Only result revisions may equal 9007199254740991. Stale, foreign, untyped or denied results raise `AuthorityDenied`.

Register explicit functions with `register_enterprise_adapters` / `registerEnterpriseAdapters`. Tenant and identity callbacks return a matching immutable context. Quota and credit adapters expose all three methods: `reserve`, `commit`, `reconcile`. Payment callbacks accept only immutable verified `PaymentEvent` instances and return a bound `AuthorityResult`. Registration performs no calls. There is no plugin discovery, runtime module loading or routing language. The initial tenant callback preserves the existing single principal and grants revision, denies organisation/team scope, and provides no identity, quota, credit or payment authority. Passing a missing callback denies access. Registration and the preview flag never activate enterprise enforcement on existing requests; authentication, key controls and budgets remain authoritative.

Concrete authorities must atomically compare the revision, validate the current grants revision and scoped ownership, and persist the operation ID with the state change. Repeated IDs return the original bound result without a second mutation. A later lifecycle step uses a new operation ID and the prior successor revision. Conflicts deny; transport errors propagate and do not permit automatic replay. These modules validate input and result bindings but contain no storage, CAS implementation or deduplication ledger.

IdentityAssertion records pinned issuer, subject, audience, request, nonce and expiry. Its trusted producer must verify signature, issuer/audience, recipient, clock expiry and single use before construction. PaymentEvent records processor/event IDs, context, scoped ID, expected revision, idempotency ID, kind (`credit`, `refund`, `dispute`), uppercase three-letter currency and integer amount. Its trusted producer must verify the processor signature and merchant/currency/event binding before construction. `verified: true` is a typed attestation from that trusted producer, not signature verification and never a field accepted directly from public JSON. The identity authority must bind the assertion subject to the requested principal and scope. No webhook, SAML verifier, organisational data, ledger, migration or payment processing is supplied here.

## Cost, errors and retention

The descriptor makes no provider, database, billing or processor calls and incurs no generation cost. It includes no identity, credential, prompt, response or payment details and creates no stored data. Contract calls have no retry policy; callers must handle denial and uncertainty without fabricating success. Concrete integrations own storage retention and audit policies. These contracts do not certify provider metering, merchant processing or deployed enterprise capabilities.

## Shared contract vectors

Both test suites read the following synthetic vectors directly. All IDs and values are fixtures.

```json
[
  {
    "name": "legacy context",
    "type": "TenantContext",
    "data": {
      "principal_id": "principal:one",
      "grants_revision": 4
    },
    "valid": true
  },
  {
    "name": "org team context",
    "type": "TenantContext",
    "data": {
      "principal_id": "principal:one",
      "grants_revision": 4,
      "org_id": "org:one",
      "team_id": "team:one"
    },
    "valid": true
  },
  {
    "name": "team without org",
    "type": "TenantContext",
    "data": {
      "principal_id": "principal:one",
      "grants_revision": 4,
      "team_id": "team:one"
    },
    "valid": false
  },
  {
    "name": "empty principal",
    "type": "TenantContext",
    "data": {
      "principal_id": "",
      "grants_revision": 4
    },
    "valid": false
  },
  {
    "name": "boolean revision",
    "type": "TenantContext",
    "data": {
      "principal_id": "principal:one",
      "grants_revision": true
    },
    "valid": false
  },
  {
    "name": "negative revision",
    "type": "TenantContext",
    "data": {
      "principal_id": "principal:one",
      "grants_revision": -1
    },
    "valid": false
  },
  {
    "name": "operation",
    "type": "AuthorityOperation",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "operation_id": "operation:one",
      "amount": 12
    },
    "valid": true
  },
  {
    "name": "empty operation id",
    "type": "AuthorityOperation",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "operation_id": "",
      "amount": 12
    },
    "valid": false
  },
  {
    "name": "fractional revision",
    "type": "AuthorityOperation",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 1.5,
      "operation_id": "operation:one",
      "amount": 12
    },
    "valid": false
  },
  {
    "name": "unsafe revision",
    "type": "AuthorityOperation",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 9007199254740991,
      "operation_id": "operation:one",
      "amount": 12
    },
    "valid": false
  },
  {
    "name": "negative units",
    "type": "AuthorityOperation",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "operation_id": "operation:one",
      "amount": -1
    },
    "valid": false
  },
  {
    "name": "verified assertion",
    "type": "IdentityAssertion",
    "data": {
      "issuer_id": "issuer:one",
      "subject_id": "subject:one",
      "audience_id": "audience:one",
      "request_id": "request:one",
      "nonce_id": "nonce:one",
      "expires_at": 1000,
      "verified": true
    },
    "valid": true
  },
  {
    "name": "unverified assertion",
    "type": "IdentityAssertion",
    "data": {
      "issuer_id": "issuer:one",
      "subject_id": "subject:one",
      "audience_id": "audience:one",
      "request_id": "request:one",
      "nonce_id": "nonce:one",
      "expires_at": 1000,
      "verified": false
    },
    "valid": false
  },
  {
    "name": "missing nonce",
    "type": "IdentityAssertion",
    "data": {
      "issuer_id": "issuer:one",
      "subject_id": "subject:one",
      "audience_id": "audience:one",
      "request_id": "request:one",
      "expires_at": 1000,
      "verified": true
    },
    "valid": false
  },
  {
    "name": "verified payment",
    "type": "PaymentEvent",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "idempotency_id": "operation:one",
      "processor_id": "processor:one",
      "event_id": "event:one",
      "kind": "credit",
      "currency": "USD",
      "amount": 12,
      "verified": true
    },
    "valid": true
  },
  {
    "name": "unverified payment",
    "type": "PaymentEvent",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "idempotency_id": "operation:one",
      "processor_id": "processor:one",
      "event_id": "event:one",
      "kind": "credit",
      "currency": "USD",
      "amount": 12,
      "verified": false
    },
    "valid": false
  },
  {
    "name": "payment idempotency",
    "type": "PaymentEvent",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "idempotency_id": "",
      "processor_id": "processor:one",
      "event_id": "event:one",
      "kind": "credit",
      "currency": "USD",
      "amount": 12,
      "verified": true
    },
    "valid": false
  },
  {
    "name": "payment currency",
    "type": "PaymentEvent",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "idempotency_id": "operation:one",
      "processor_id": "processor:one",
      "event_id": "event:one",
      "kind": "credit",
      "currency": "usd",
      "amount": 12,
      "verified": true
    },
    "valid": false
  },
  {
    "name": "bound decision",
    "type": "AuthorityResult",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 8,
      "operation_id": "operation:one",
      "allowed": true
    },
    "valid": true
  },
  {
    "name": "unknown context field",
    "type": "TenantContext",
    "data": {
      "principal_id": "principal:one",
      "grants_revision": 4,
      "extra": "value"
    },
    "valid": false
  },
  {
    "name": "identifier newline",
    "type": "TenantContext",
    "data": {
      "principal_id": "principal:one\n",
      "grants_revision": 4
    },
    "valid": false
  },
  {
    "name": "long identifier",
    "type": "TenantContext",
    "data": {
      "principal_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "grants_revision": 4
    },
    "valid": false
  },
  {
    "name": "identifier upper bound",
    "type": "TenantContext",
    "data": {
      "principal_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "grants_revision": 4
    },
    "valid": true
  },
  {
    "name": "string revision",
    "type": "AuthorityOperation",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": "7",
      "operation_id": "operation:one",
      "amount": 12
    },
    "valid": false
  },
  {
    "name": "null amount",
    "type": "AuthorityOperation",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "operation_id": "operation:one",
      "amount": null
    },
    "valid": false
  },
  {
    "name": "operation upper bound",
    "type": "AuthorityOperation",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 9007199254740990,
      "operation_id": "operation:one",
      "amount": 12
    },
    "valid": true
  },
  {
    "name": "currency newline",
    "type": "PaymentEvent",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "idempotency_id": "operation:one",
      "processor_id": "processor:one",
      "event_id": "event:one",
      "kind": "credit",
      "currency": "USD\n",
      "amount": 12,
      "verified": true
    },
    "valid": false
  },
  {
    "name": "nonboolean attestation",
    "type": "PaymentEvent",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "idempotency_id": "operation:one",
      "processor_id": "processor:one",
      "event_id": "event:one",
      "kind": "credit",
      "currency": "USD",
      "amount": 12,
      "verified": 1
    },
    "valid": false
  },
  {
    "name": "unknown payment kind",
    "type": "PaymentEvent",
    "data": {
      "context": {
        "principal_id": "principal:one",
        "grants_revision": 4
      },
      "scoped_id": "resource:one",
      "revision": 7,
      "idempotency_id": "operation:one",
      "processor_id": "processor:one",
      "event_id": "event:one",
      "kind": "transfer",
      "currency": "USD",
      "amount": 12,
      "verified": true
    },
    "valid": false
  }
]```
