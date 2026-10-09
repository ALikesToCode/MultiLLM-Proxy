-- Reviewed configuration only. No keys, headers, connection profiles or request content.
CREATE TABLE IF NOT EXISTS config_snapshot_revisions (
  domain TEXT PRIMARY KEY CHECK(domain = 'auto_routes'),
  revision INTEGER NOT NULL CHECK(revision >= 0 AND revision <= 9007199254740991)
);
CREATE TABLE IF NOT EXISTS config_snapshots (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL CHECK(domain = 'auto_routes'),
  base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
  configuration TEXT NOT NULL CHECK(json_valid(configuration)),
  base_fingerprint TEXT NOT NULL CHECK(length(base_fingerprint) = 64),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK(size_bytes > 0 AND size_bytes <= 262144)
);
CREATE INDEX IF NOT EXISTS config_snapshots_domain_created ON config_snapshots(domain, created_at, id);
CREATE TABLE IF NOT EXISTS config_snapshot_applications (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL CHECK(domain = 'auto_routes'),
  snapshot_id TEXT NOT NULL REFERENCES config_snapshots(id),
  base_revision INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  applied_at TEXT NOT NULL,
  applied_by TEXT NOT NULL,
  UNIQUE(domain, revision)
);
