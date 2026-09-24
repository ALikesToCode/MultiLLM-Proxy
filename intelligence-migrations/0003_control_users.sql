CREATE TABLE IF NOT EXISTS control_users (
  username TEXT PRIMARY KEY,
  api_key_hash TEXT NOT NULL,
  api_key_prefix TEXT NOT NULL,
  scopes TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0, 1)),
  created_at TEXT NOT NULL,
  last_login TEXT,
  last_used_at TEXT,
  last_used_ip TEXT,
  created_by TEXT,
  rotated_at TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_users_api_key_prefix ON control_users(api_key_prefix);
