-- Append-only record of dashboard account writes. The Worker exposes no statement that
-- updates or deletes these rows, so the Container cannot erase its own history.
CREATE TABLE IF NOT EXISTS control_user_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN ('upsert', 'delete')),
  outcome TEXT NOT NULL CHECK(outcome IN ('stored', 'deleted', 'missing', 'refused')),
  username TEXT NOT NULL,
  is_admin INTEGER CHECK(is_admin IS NULL OR is_admin IN (0, 1)),
  scopes TEXT,
  api_key_prefix TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_user_audit_username ON control_user_audit(username, id);
