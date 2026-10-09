-- Numeric alert evidence; webhook addresses are private configuration only.
CREATE TABLE IF NOT EXISTS gateway_alert_rules (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  revision INTEGER NOT NULL CHECK(revision > 0 AND revision < 9007199254740991),
  configuration TEXT NOT NULL CHECK(length(configuration) <= 8192),
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_alert_events (
  dedupe_key TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  payload TEXT NOT NULL CHECK(length(payload) <= 8192),
  created_at REAL NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending', 'delivered', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
  attempt_times TEXT NOT NULL DEFAULT '[]' CHECK(length(attempt_times) <= 128),
  last_attempt_at REAL,
  next_attempt_at REAL NOT NULL,
  claim_token TEXT,
  lease_until REAL NOT NULL DEFAULT 0,
  error_code TEXT
);
CREATE INDEX IF NOT EXISTS gateway_alert_events_due ON gateway_alert_events(state, next_attempt_at, lease_until);
CREATE INDEX IF NOT EXISTS gateway_alert_events_retention ON gateway_alert_events(created_at);
