-- Scoped hashes, reviewed route identifiers and bounded turn markers only.
CREATE TABLE IF NOT EXISTS session_tiers (
  scope_hash TEXT PRIMARY KEY CHECK(length(scope_hash) = 64),
  lane TEXT NOT NULL CHECK(lane IN ('main', 'delegation', 'aux')),
  tier INTEGER NOT NULL CHECK(tier >= 0 AND tier <= 100),
  approved_model TEXT NOT NULL CHECK(length(approved_model) <= 256),
  actual_model TEXT NOT NULL CHECK(length(actual_model) <= 256),
  policy_revision TEXT NOT NULL CHECK(length(policy_revision) = 64),
  expires_at REAL NOT NULL,
  safe_turn INTEGER NOT NULL CHECK(safe_turn IN (0, 1)),
  pending_tools TEXT NOT NULL CHECK(json_valid(pending_tools) AND length(pending_tools) <= 9000),
  lease TEXT NOT NULL CHECK(length(lease) <= 64)
);
CREATE INDEX IF NOT EXISTS session_tiers_expiry ON session_tiers(expires_at);
