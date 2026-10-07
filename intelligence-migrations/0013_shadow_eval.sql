-- Opt-in sampling; NULL is equivalent to zero.
ALTER TABLE control_users ADD COLUMN shadow_eval_rate REAL
  CHECK (shadow_eval_rate IS NULL OR (shadow_eval_rate >= 0 AND shadow_eval_rate <= 0.2));
CREATE TABLE IF NOT EXISTS shadow_eval_samples (
  id TEXT PRIMARY KEY, created_at REAL NOT NULL, document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shadow_eval_samples_time ON shadow_eval_samples(created_at, id);
CREATE TABLE IF NOT EXISTS shadow_eval_results (
  id TEXT PRIMARY KEY, sample_id TEXT NOT NULL, candidate TEXT NOT NULL,
  created_at REAL NOT NULL, document TEXT,
  UNIQUE(sample_id, candidate)
);
CREATE INDEX IF NOT EXISTS idx_shadow_eval_results_time ON shadow_eval_results(created_at, id);
CREATE TABLE IF NOT EXISTS shadow_eval_config (
  id INTEGER PRIMARY KEY CHECK (id = 1), document TEXT NOT NULL,
  day INTEGER NOT NULL DEFAULT 0, replay_count INTEGER NOT NULL DEFAULT 0,
  lease_until REAL NOT NULL DEFAULT 0, lease_owner TEXT
);
CREATE TABLE IF NOT EXISTS shadow_eval_policy_backups (
  id TEXT PRIMARY KEY, created_at REAL NOT NULL, document TEXT NOT NULL
);
