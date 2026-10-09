CREATE TABLE IF NOT EXISTS usage_receipt_keys (
    key_id TEXT PRIMARY KEY,
    public_key_base64 TEXT NOT NULL,
    reviewed INTEGER NOT NULL DEFAULT 0 CHECK (reviewed IN (0, 1))
);
CREATE TABLE IF NOT EXISTS usage_receipt_heads (
    principal TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    record_hash TEXT
);
CREATE TABLE IF NOT EXISTS usage_receipts (
    id TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    event_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    previous_hash TEXT,
    key_id TEXT NOT NULL REFERENCES usage_receipt_keys(key_id),
    receipt_json TEXT NOT NULL,
    UNIQUE (principal, sequence),
    UNIQUE (principal, event_id)
);
CREATE INDEX IF NOT EXISTS idx_usage_receipts_principal ON usage_receipts(principal, sequence);
