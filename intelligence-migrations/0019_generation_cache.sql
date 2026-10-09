-- Shared exact generation metadata; complete response bodies live in the media bucket.
CREATE TABLE IF NOT EXISTS generation_cache (
  principal_hash TEXT NOT NULL,
  cache_key TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  model TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  body_pointer TEXT NOT NULL,
  body_bytes INTEGER NOT NULL CHECK (body_bytes >= 1 AND body_bytes <= 1048576),
  body_hash TEXT NOT NULL,
  metadata TEXT NOT NULL,
  PRIMARY KEY (principal_hash, cache_key),
  CHECK (expires_at > created_at AND expires_at <= created_at + 300)
);
CREATE INDEX IF NOT EXISTS generation_cache_expiry ON generation_cache (expires_at);
