CREATE TABLE IF NOT EXISTS realtime_tickets (
  nonce TEXT PRIMARY KEY, principal_hash TEXT NOT NULL, owner TEXT NOT NULL,
  credential_kind TEXT NOT NULL, credential_fingerprint TEXT NOT NULL,
  model TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS realtime_ticket_expiry ON realtime_tickets(expires_at);
CREATE TABLE IF NOT EXISTS realtime_sessions (
  id TEXT PRIMARY KEY, principal_hash TEXT NOT NULL, owner TEXT NOT NULL, model TEXT NOT NULL,
  lease_id TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, lease_until INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('admitted','active','settled','unknown','released')),
  input_text_tokens INTEGER, input_audio_tokens INTEGER, output_text_tokens INTEGER, output_audio_tokens INTEGER,
  cost_usd REAL, closed_at INTEGER
);
CREATE INDEX IF NOT EXISTS realtime_session_scope ON realtime_sessions(principal_hash,state,lease_until);
