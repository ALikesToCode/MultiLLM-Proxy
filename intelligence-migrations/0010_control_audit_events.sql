-- Append-only dashboard security events: sign-ins (password and Cloudflare Access),
-- sign-outs, refused single sign-on attempts and administrator setting changes. Account
-- writes stay in control_user_audit. The Worker exposes no statement that updates or
-- deletes these rows.
CREATE TABLE IF NOT EXISTS control_audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT,
  action TEXT NOT NULL CHECK(action IN ('sign_in', 'sign_out', 'setting_change')),
  outcome TEXT NOT NULL CHECK(outcome IN ('succeeded', 'refused')),
  target TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_control_audit_events_actor ON control_audit_events(actor, id);
CREATE INDEX IF NOT EXISTS idx_control_audit_events_target ON control_audit_events(target, id);
CREATE INDEX IF NOT EXISTS idx_control_audit_events_action ON control_audit_events(action, id);
