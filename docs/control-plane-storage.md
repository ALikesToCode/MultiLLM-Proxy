# Control-plane persistence

Local installations keep SQLite by default. Set `CONTROL_PLANE_DATABASE_URL`
through the deployment's secret manager to use PostgreSQL for users, key hashes,
model overrides, automatic routes, quotas, and workbench settings. Use a dedicated
database account with access only to this application's `multillm` schema and
require TLS for remote databases. A configured but unavailable database fails
closed: it never silently switches to an empty local database.

Container disk is ephemeral. PostgreSQL must be external to the Container;
changing this setting does not provision a database or migrate existing records.
Deploying without migrating existing authentication records can lock users out.

## Dashboard accounts in D1

On Cloudflare, dashboard accounts (usernames, scopes, key hashes and usage
metadata) can live in the `control_users` table of the `INTELLIGENCE_DB` D1
database, so Access keys survive Container sleep and redeploys. This is an explicit
opt-in: set `AUTH_STORAGE_BACKEND=d1` (the repository's `wrangler.jsonc` does). The
D1 binding alone never switches the account store, because D1 accounts need their
migration and switching a deployment implicitly once caused an outage. Without the
setting, accounts stay in SQLite or PostgreSQL. The Container reaches the table only
through the private `intelligence.internal/v1/users` operations (list, get, by
prefix, upsert, delete, touch), never with SQL. The edge reads the same table to
verify Knowledge requests.

Only usernames the Worker's own configuration names can hold administration:
`ADMIN_USERNAME` and the optional comma-separated `ADMIN_USERNAMES`. The Worker
refuses to store `is_admin` or the `admin` scope for any other username (the
dashboard reports 403 `admin_not_allowed`), and the edge grants management scopes
only to those names, so a compromised Container cannot persist an administrator.
Add a username to `ADMIN_USERNAMES` before making it an administrator. Every account
write and refusal is appended to `control_user_audit`; the Worker exposes no
statement that changes or deletes audit rows. Sign-ins, sign-outs, refused single
sign-on and administrator setting changes go to `control_audit_events` through the
`audit_record` operation, and administrators read both tables on the audit log page
through the read-only `audit_list` operation; see
[Dashboard single sign-on and the audit log](dashboard-sso.md).

`ADMIN_API_KEY` is the bootstrap credential. It authenticates from the environment
even when D1 is slow or unavailable, and startup writes its account record back. Other
dashboard keys fail closed with 503 while D1 is unavailable. A verified key is
remembered in the Container for up to 60 seconds, so authentication does not wait on
D1 for every request; account changes made in the dashboard apply immediately, and
changes made directly in D1 apply within that minute. Last-used times are advisory
and written at most once a minute per key and address.

Apply every migration before deploying (`npm run deploy` does it, see
[Cloudflare deployment](cloudflare-containers.md#deploy)); `/ready` answers 503 with
the missing tables until they exist. An unavailable D1 never falls back to local
SQLite. Existing SQLite accounts are not migrated; on Cloudflare they were already
lost with the Container disk. Encrypted control-plane backups do not include D1
accounts: recover them through Cloudflare's D1 tooling.

## Automatic routes in D1

When the Worker provides its durable intelligence store (`INTELLIGENCE_DB`),
operator edits to automatic routes are saved in the `auto_routes` D1 table through
the private `intelligence.internal/v1/auto-routes` operations, so they survive
Container sleep and redeploys. Seeded defaults apply to any route without a stored
row. The Container caches routes for 30 seconds. If D1 cannot be read, routing uses
the last stored copy, or the seeded defaults if there is none, and a save fails with
503 instead of being kept only on Container disk.

## Control-plane state in D1

When the Worker provides `INTELLIGENCE_DB`, the rest of the Container's control-plane
state lives in D1 too (migration `0006_control_state.sql`), behind fixed operations
under `intelligence.internal/v1/state/`. It survives Container sleep and redeploys and
is shared by every Container instance. Without D1 the same state stays in SQLite or
PostgreSQL as before. When both are configured, D1 is used, as for automatic routes.

| State | D1 tables | How the Container reads it |
| --- | --- | --- |
| Request usage: per-minute, token and daily limits | `control_rate_usage`, `control_rate_flushes` | In-memory ledger with background sync |
| Login throttling | `control_login_attempts` | On every sign-in attempt, with the local record as a floor |
| Disabled models | `control_model_overrides` | 30-second read-through cache |
| Free-route cooldowns | `control_free_cooldowns` | In memory, written and refreshed in the background |
| Workbench profiles and comparison results | `control_connection_profiles`, `control_comparison_results` | 30-second read-through cache per owner |
| Provider model catalog | `control_provider_catalog` | Last good snapshot per provider, checked every 60 seconds |

### Limits without a D1 round trip

Rate limits and cooldowns are checked on every request, so neither waits on D1.
Each process admits requests against an in-memory ledger that holds the requests it
admitted itself, plus a cached figure for the usage every other ledger recorded:
other Container instances, and this Container's earlier processes before a restart.
One background thread per process sends this process's usage to D1 as atomic
per-minute and per-hour increments every `RATE_LIMIT_SYNC_SECONDS` (default 5, 1 to
60) while there is traffic. The same call returns the other ledgers' usage for the
identities this process is serving. A new cooldown applies at once and is written on
the next background tick; the shared cooldown list is refreshed every 10 seconds while
the free pool is in use, and D1 keeps the later expiry when instances disagree.

This trades exactness for latency:

- Another instance's usage becomes visible after at most one sync interval plus a
  round trip. A burst spread across instances within that time can exceed a limit by
  what the other instances admitted meanwhile.
- After a restart, an identity is admitted on this process's own counts until its
  first refresh, which is requested at once and normally arrives within a second. A
  client already at its daily budget can get a few more requests through then.
- Other instances' per-minute usage is estimated from minute buckets (the current
  minute plus the overlapping part of the previous one). Their daily usage comes from
  hour buckets and covers the last 23 to 24 hours.
- Usage admitted in the last interval before a crash can be lost; a graceful stop
  sends it. A flush carries an ID that D1 records, so a flush resent after a lost reply
  is counted once.
- Another instance's cooldown can take one refresh interval to arrive, so one extra
  upstream attempt may reach a provider that is already cooling down.

Usage rows hold a keyed hash of the identity (HMAC with `JWT_SECRET`), never a
username, key prefix or client address. Rotating `JWT_SECRET` starts the shared counts
afresh. Usage rows are pruned after about a day.

### Login throttling

Every sign-in attempt is recorded in the local store and, through one atomic Worker
statement, in `control_login_attempts`, so failures against any instance count toward
the same lockout and survive restarts. A decision uses the stricter of the two
records. If D1 cannot be reached, the local record still throttles and a warning is
logged: an outage never switches throttling off, and never blocks sign-in on its own.

### Outages and unapplied migrations

A D1 outage, or code deployed before migration `0006` is applied, never takes the
gateway down. Each store logs a warning and keeps working from memory:

- Limits use this process's own counts and the last shared figures (ignored once they
  are 15 minutes old) and retry after 30 seconds. Cooldowns keep this process's own
  and the last shared copy, and unsent cooldowns are written once D1 answers.
- Disabled models, workbench lists and the provider catalog use the last copy this
  process read. Before its first successful read, no model is disabled, workbench
  lists answer 503 rather than an empty list, and the catalog starts empty until the
  next refresh.
- Admin saves (disabling a model, saving a profile or a comparison) answer 503 and are
  not kept only in this process. A catalog refresh that cannot be stored stays in this
  Container, and its refresh result says so.

`/ready` reports the missing tables until the migration is applied.

Model override reads bypass the process-local cache in PostgreSQL mode so another
replica's changes are visible. Short control-plane transactions use a database-wide
advisory lock, matching SQLite's single-writer semantics for quota reservations.
Provider streaming does not hold that lock.

The intelligence gateway can store its reviewed policy and allowance reservations
here. Containers may instead use the dedicated [D1 intelligence store](intelligence-d1.md)
for policy, reservations and integration principals.

Encrypted control-plane backups include the SQLite/PostgreSQL intelligence tables;
older version-one backups restore with empty intelligence tables. They do not capture
or restore D1 records, including the control-plane state above. Manage D1 recovery separately through Cloudflare. See
[intelligence configuration](intelligence-gateway.md).

## Encrypted backups and an empty-destination migration

These are operator-only commands, not dashboard downloads. Backups include key
hashes and account metadata. Supply `CONTROL_PLANE_BACKUP_KEY` as a Fernet key from
a secret manager and keep it separately from the encrypted backup. The command
does not load `.env` files or print records or credentials.

1. Stop application writers. For SQLite, the four databases are separate files,
   so maintenance mode is required for a consistent cross-store snapshot.
2. With the source environment selected, run
   `python scripts/control_plane_backup.py backup snapshot.control-plane-backup`.
   Creation is exclusive with owner-only permissions; existing files are refused.
3. Validate with `python scripts/control_plane_backup.py check snapshot.control-plane-backup`.
4. Select a **new, empty** destination using the database URL or SQLite paths.
   Run `python scripts/control_plane_backup.py restore-empty snapshot.control-plane-backup --apply`.
   A populated destination is rejected; there is no merge or replacement mode.
5. Verify accounts and settings in the destination before starting writers. Retain
   the stopped source for rollback; switching back after new writes requires a new
   migration to avoid losing those writes.

PostgreSQL restore is one transaction. SQLite destination files commit separately;
if a commit fails, discard only that newly created destination and retry into another
empty destination. Never retry against or delete an existing production database.
For datasets beyond the 32 MiB backup limit, use database-native encrypted backups.
Backups and private `example.json` are excluded from Git and the Container image.

Roleplay session state remains in Cloudflare Durable Objects, not this backup.
Provider secrets remain in the deployment secret store. This feature neither
exports those secrets nor changes the configured upstream credentials.
