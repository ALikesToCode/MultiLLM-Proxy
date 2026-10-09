CREATE TABLE IF NOT EXISTS saml_requests (
  state_digest TEXT PRIMARY KEY,
  nonce_digest TEXT NOT NULL,
  recipient_digest TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  claimed_at INTEGER,
  CHECK(expires_at > created_at AND expires_at <= created_at + 300)
);
CREATE INDEX IF NOT EXISTS idx_saml_requests_expiry ON saml_requests(expires_at);

CREATE TABLE IF NOT EXISTS saml_subject_links (
  id TEXT PRIMARY KEY,
  issuer_digest TEXT NOT NULL,
  subject_digest TEXT NOT NULL,
  account TEXT NOT NULL REFERENCES control_users(username),
  org_id TEXT,
  team_id TEXT,
  grants_revision INTEGER NOT NULL DEFAULT 0 CHECK(grants_revision >= 0),
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(team_id IS NULL OR org_id IS NOT NULL),
  UNIQUE(issuer_digest, subject_digest)
);
CREATE INDEX IF NOT EXISTS idx_saml_subject_links_account ON saml_subject_links(account, active);

CREATE TABLE IF NOT EXISTS saml_audit (
  id TEXT PRIMARY KEY,
  issuer_digest TEXT NOT NULL,
  account TEXT,
  actor_digest TEXT,
  outcome TEXT NOT NULL,
  occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_saml_audit_time ON saml_audit(occurred_at);
