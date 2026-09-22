CREATE TABLE IF NOT EXISTS intelligence_principals (
  id TEXT PRIMARY KEY,
  scopes TEXT NOT NULL,
  version INTEGER NOT NULL CHECK(version >= 1),
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS intelligence_credentials (
  principal_id TEXT NOT NULL REFERENCES intelligence_principals(id),
  version INTEGER NOT NULL,
  key_prefix TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL,
  PRIMARY KEY(principal_id, version)
);
