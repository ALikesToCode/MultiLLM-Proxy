-- Content-free counters. auto_routes retains its W13 counter for snapshot CAS.
CREATE TABLE IF NOT EXISTS control_revisions (
  domain TEXT PRIMARY KEY CHECK(domain IN ('model_overrides', 'provider_catalog', 'key_controls', 'model_grants')),
  revision INTEGER NOT NULL CONSTRAINT revision_cas_confirmed CHECK(revision >= 0 AND revision <= 9007199254740991),
  updated_at TEXT NOT NULL
);
