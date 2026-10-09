-- Scoped semantic metadata; response content stays in the existing media bucket.
CREATE TABLE IF NOT EXISTS semantic_generation_cache (
    principal_hash TEXT NOT NULL,
    entry_id TEXT NOT NULL,
    partition_hash TEXT NOT NULL,
    model_revision TEXT NOT NULL,
    vector TEXT NOT NULL,
    guard_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    body_pointer TEXT NOT NULL,
    body_bytes INTEGER NOT NULL CHECK (body_bytes BETWEEN 1 AND 1048576),
    body_hash TEXT NOT NULL,
    metadata TEXT NOT NULL,
    PRIMARY KEY (principal_hash, entry_id),
    CHECK (expires_at > created_at AND expires_at <= created_at + 300)
);
CREATE INDEX IF NOT EXISTS semantic_generation_cache_partition
    ON semantic_generation_cache (principal_hash, partition_hash, model_revision, expires_at);
CREATE INDEX IF NOT EXISTS semantic_generation_cache_oldest
    ON semantic_generation_cache (principal_hash, created_at, entry_id);
CREATE INDEX IF NOT EXISTS semantic_generation_cache_expiry
    ON semantic_generation_cache (expires_at);
