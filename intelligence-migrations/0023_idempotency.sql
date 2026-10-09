-- Durable claims remain as tombstones when replay content expires.
CREATE TABLE IF NOT EXISTS managed_idempotency (
    scope TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'unknown')),
    handed_off INTEGER NOT NULL DEFAULT 0 CHECK (handed_off IN (0, 1)),
    created_at INTEGER NOT NULL,
    pending_until INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    response_key TEXT,
    response_digest TEXT
);
CREATE INDEX IF NOT EXISTS managed_idempotency_expiry
    ON managed_idempotency (status, expires_at);
