-- Only a completed row can expose its immutable response body.
CREATE TABLE IF NOT EXISTS hosted_responses (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('writing', 'failed', 'completed', 'deleting')),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    parent_id TEXT,
    policy_revision TEXT NOT NULL,
    depth INTEGER NOT NULL CHECK (depth BETWEEN 1 AND 16),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    body_key TEXT NOT NULL,
    body_bytes INTEGER NOT NULL CHECK (body_bytes BETWEEN 1 AND 1048576),
    body_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS hosted_responses_owner_expiry ON hosted_responses (owner, expires_at);
