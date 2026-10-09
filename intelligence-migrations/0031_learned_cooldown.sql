-- Opaque identities and bounded, expiring cooldown evidence.
CREATE TABLE IF NOT EXISTS learned_cooldown (
    bucket_digest TEXT PRIMARY KEY,
    credential_digest TEXT NOT NULL,
    lower_seconds INTEGER NOT NULL CHECK (lower_seconds BETWEEN 1 AND 3600),
    upper_seconds INTEGER NOT NULL CHECK (upper_seconds BETWEEN lower_seconds AND 3600),
    trial_seconds INTEGER NOT NULL CHECK (trial_seconds BETWEEN 1 AND 3600),
    samples INTEGER NOT NULL CHECK (samples BETWEEN 0 AND 2147483647),
    consistent INTEGER NOT NULL CHECK (consistent BETWEEN 0 AND 3),
    steps INTEGER NOT NULL CHECK (steps BETWEEN 0 AND 12),
    confident INTEGER NOT NULL CHECK (confident IN (0, 1)),
    last_kind TEXT NOT NULL,
    last_throttle REAL,
    last_observed REAL NOT NULL,
    floor_until REAL NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 2147483647)
);
CREATE INDEX IF NOT EXISTS learned_cooldown_expiry ON learned_cooldown (expires_at);
