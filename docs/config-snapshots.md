# Control configuration snapshots

`CONFIG_SNAPSHOTS_ENABLED` defaults to false. All snapshot paths return 404
while disabled, and existing auto-route saves keep their current payload,
storage and response behavior. No provider calls or generation are involved.

The public administration paths run in Flask for both direct administration
and Worker-forwarded Container traffic. They use the existing session login,
administrator check and CSRF protection. They are not gateway-key API routes.
The existing private `auto_routes` adapter stores configuration in D1; there is
no new public Worker dispatch or private outbound endpoint.

Before enabling, apply `intelligence-migrations/0015_config_snapshots.sql`
(`npx wrangler d1 migrations apply multillm-intelligence --remote`), and configure
`INTELLIGENCE_STORAGE_BACKEND=d1` for Flask. Enable the flag on both Worker
and Container. Enabled snapshots without durable D1 or any required table
fail closed with JSON HTTP 503. Enabled ordinary D1 route saves also fail
closed if the snapshot migration is missing. Local SQLite/PostgreSQL snapshot
storage is outside this initial private-D1 implementation boundary.

## Review and apply

`GET /admin/config/snapshots` returns `current_revision`, snapshot metadata,
and the latest 100 application audit records. It never includes stored
configuration documents or account objects. The only supported domain is
`auto_routes`; its revision begins at zero when the feature is introduced.

Create a review with `POST /admin/config/snapshots`:

```json
{"domain":"auto_routes","base_revision":0,"configuration":{"routes":[{"route_id":"auto:review","candidates":["openai:model-a","nanogpt:model-b"]}]}}
```

HTTP 201 returns the immutable snapshot metadata and ID. Creation requires
that `base_revision` still matches; it does not activate any route.
Configuration is a patch containing only the listed route IDs and their
ordered candidate model IDs. Omitted routes and seeded defaults remain active.
No deletion or wholesale replacement is performed.

`GET /admin/config/snapshots/<id>/diff` returns only route IDs and the approved
before/after model ID lists, plus the base and current revisions. Flask displays
the effective seeded defaults when there is no durable override. Diff pages
contain at most 20 routes; use `?offset=<next_offset>` until `next_offset` is
null. A review spanning pages must be restarted if `current_revision` changes.
An unknown snapshot returns 404.

Apply with `POST /admin/config/snapshots/<id>/apply`:

```json
{"current_revision":0,"confirm":true}
```

Both literal `confirm=true` and the current integer revision are required.
A mismatch, stale review, repeat application, or patch that would exceed the
existing 200-row durable route read bound returns 409. The snapshot base
must equal the submitted revision. The transactional D1 batch compares the
revision and exact durable route state, writes the reviewed routes, increments
the revision, and appends an audit record with an opaque administrator digest.
A route write failure rolls back the revision, audit and route updates together.
Ordinary enabled D1 route saves advance the same revision. A fingerprint also
rejects a review if routes were saved while the flag was temporarily disabled.

A successful apply clears this Container’s route cache. Other Containers can
retain their last-good route copy for the existing 30-second cache interval;
an outage preserves their last-good routing. There is no cluster-wide immediate
cache invalidation. Seeded candidate orders retired by the existing auto-route
service are rejected at creation, rather than claiming an apply that the route
service would subsequently replace with current defaults.

To roll back, create a new snapshot containing the previous candidate order
at the current revision, review its diff and explicitly apply it. Historical
snapshots and application records are retained; rollback adds a revision.

## Bounds, secrets and errors

There are at most 100 snapshots per domain. Each configuration is bounded to
256 KiB, 200 routes and 16 distinct candidates per route; model IDs are bounded
to 256 characters. The existing private transport also bounds its complete
request envelope to 256 KiB, so configurations at that boundary require room
for metadata. Oversized requests return 413. Count exhaustion or a concurrent
revision change at creation returns 409. No automatic archival or deletion is
performed and there is no delete endpoint: once a domain has 100 snapshots,
creation returns 409 until unapplied snapshots are removed from D1 (applied
ones are referenced by their audit records). Application records are append-only and grow with
successful applies; list responses are bounded to the latest 100 records.

Only the exact route configuration schema is accepted. Provider keys, gateway
keys, headers, prompts, connections, environment fields and arbitrary metadata
are rejected, not redacted into storage. Known credential-shaped identifiers
are also rejected. Snapshots contain configuration, a durable-state digest and
opaque administrator attribution only; no runtime account or environment
objects are read into snapshot documents.

Malformed configuration returns 400, non-admin sessions return 403, and
unauthenticated sessions follow the existing login flow. Every snapshot response
uses `Cache-Control: no-store`. Storage failures return JSON 503 with
`config_snapshot_storage_unavailable`; they do not claim a completed apply.
Private submissions are never retried. If a response is lost after submission,
check the current revision and audit records before making a new review.

Snapshot operations consume D1 reads/writes and bounded private transport
capacity. They make no upstream generation calls, but D1 usage can have storage
and request costs.
