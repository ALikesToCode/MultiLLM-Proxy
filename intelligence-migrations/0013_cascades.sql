-- Verification-gated routes share the automatic-route control-plane database.
CREATE TABLE IF NOT EXISTS cascades (
    name TEXT PRIMARY KEY,
    config TEXT NOT NULL CHECK (json_valid(config)),
    updated_at TEXT NOT NULL
);
