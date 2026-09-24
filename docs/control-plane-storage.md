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
metadata) live in the `control_users` table of the `INTELLIGENCE_DB` D1 database,
so Access keys survive Container sleep and redeploys. The Worker selects this with
`AUTH_STORAGE_BACKEND=d1` whenever the D1 binding exists and
`CONTROL_PLANE_DATABASE_URL` is not configured; set `AUTH_STORAGE_BACKEND=sql` to
keep accounts in SQLite or PostgreSQL. The Container reaches the table only through
the private `intelligence.internal/v1/users` operations (list, get, by prefix,
upsert, delete, touch), never with SQL. The edge reads the same table to verify
Knowledge requests, and the environment-managed `ADMIN_API_KEY` account is written
at startup or on its first use.

Apply `intelligence-migrations/0003_control_users.sql` before deploying code that
selects D1 (`npx wrangler d1 migrations apply multillm-intelligence --remote`);
without it every account lookup fails closed with 503. An unavailable D1 never
falls back to local SQLite. Last-used times are advisory and written at most once a
minute per key and address. Existing SQLite accounts are not migrated; on Cloudflare
they were already lost with the Container disk. Rate limits, model overrides and
other control-plane tables still use SQLite, and encrypted control-plane backups
do not include D1 accounts: recover them through Cloudflare's D1 tooling.
Model override reads bypass the process-local cache in PostgreSQL mode so another
replica's changes are visible. Short control-plane transactions use a database-wide
advisory lock, matching SQLite's single-writer semantics for quota reservations.
Provider streaming does not hold that lock.

The intelligence gateway can store its reviewed policy and allowance reservations
here. Containers may instead use the dedicated [D1 intelligence store](intelligence-d1.md)
for policy, reservations and integration principals. This D1 binding does not move
the rest of the control plane out of SQLite or PostgreSQL.

Encrypted control-plane backups include the SQLite/PostgreSQL intelligence tables;
older version-one backups restore with empty intelligence tables. They do not capture
or restore D1 records. Manage D1 recovery separately through Cloudflare. See
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
