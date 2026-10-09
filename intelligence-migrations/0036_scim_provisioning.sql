-- Tenant-scoped external identities, retained account mappings and SCIM revisions.
CREATE TABLE IF NOT EXISTS scim_resources (
  org_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('Users', 'Groups')),
  id TEXT NOT NULL,
  external_id TEXT,
  user_name TEXT,
  display_name TEXT,
  deactivated INTEGER NOT NULL DEFAULT 0 CHECK(deactivated IN (0, 1)),
  revision INTEGER NOT NULL CONSTRAINT scim_cas_confirmed CHECK(revision BETWEEN 1 AND 9007199254740991),
  document TEXT NOT NULL,
  PRIMARY KEY(org_id, kind, id),
  UNIQUE(org_id, kind, external_id),
  UNIQUE(org_id, kind, user_name)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scim_account_identity ON scim_resources(user_name) WHERE kind='Users';
CREATE TABLE IF NOT EXISTS scim_group_members (
  org_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY(org_id, group_id, user_id)
);
CREATE TABLE IF NOT EXISTS scim_token_digests (
  org_id TEXT PRIMARY KEY,
  digest_sha256 TEXT NOT NULL CHECK(length(digest_sha256)=64),
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scim_audit (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  operation TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scim_audit_scope ON scim_audit(org_id, sequence);
