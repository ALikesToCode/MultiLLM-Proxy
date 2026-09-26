-- Control-plane state shared by every Container instance and kept across Container
-- restarts. The Container reaches these tables only through the Worker's fixed
-- intelligence.internal/v1/state operations, never with SQL.

-- Request usage flushed in the background by each Container ledger (instance), counted
-- per minute (span 60) and per hour (span 3600). Identities are keyed hashes.
CREATE TABLE IF NOT EXISTS control_rate_usage (
  identity TEXT NOT NULL,
  provider TEXT NOT NULL,
  span INTEGER NOT NULL CHECK(span IN (60, 3600)),
  bucket INTEGER NOT NULL,
  instance TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0 CHECK(requests >= 0),
  tokens INTEGER NOT NULL DEFAULT 0 CHECK(tokens >= 0),
  PRIMARY KEY (identity, provider, span, bucket, instance)
);
-- Applied usage flushes, so a flush whose reply was lost is counted once when resent.
CREATE TABLE IF NOT EXISTS control_rate_flushes (
  id TEXT PRIMARY KEY,
  at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS control_login_attempts (
  identity_hash TEXT PRIMARY KEY,
  failures INTEGER NOT NULL CHECK(failures >= 1),
  window_started REAL NOT NULL,
  locked_until REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_login_attempts_updated_at ON control_login_attempts(updated_at);
CREATE TABLE IF NOT EXISTS control_model_overrides (
  model_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('available', 'disabled')),
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS control_free_cooldowns (
  scope TEXT PRIMARY KEY,
  blocked_until REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS control_connection_profiles (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  settings TEXT NOT NULL CHECK(json_valid(settings)),
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_connection_profiles_owner ON control_connection_profiles(owner, created_at);
CREATE TABLE IF NOT EXISTS control_comparison_results (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  created_at REAL NOT NULL,
  data TEXT NOT NULL CHECK(json_valid(data))
);
CREATE INDEX IF NOT EXISTS idx_control_comparison_results_owner ON control_comparison_results(owner, created_at);
-- The last good provider model catalog, compressed and split into chunks that stay far
-- below D1's statement and row limits.
CREATE TABLE IF NOT EXISTS control_provider_catalog (
  provider TEXT NOT NULL,
  chunk INTEGER NOT NULL CHECK(chunk >= 0),
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (provider, chunk)
);
