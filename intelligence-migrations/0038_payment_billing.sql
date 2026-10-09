CREATE TABLE IF NOT EXISTS payment_checkouts (
    checkout_id TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    context_json TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    body_hash TEXT NOT NULL,
    amount_microusd INTEGER NOT NULL CHECK(amount_microusd BETWEEN 500000 AND 1000000000 AND amount_microusd % 10000 = 0),
    currency TEXT NOT NULL CHECK(currency = 'USD'),
    status TEXT NOT NULL DEFAULT 'creating',
    checkout_url TEXT,
    session_id TEXT UNIQUE,
    payment_intent TEXT UNIQUE,
    merchant TEXT,
    livemode INTEGER,
    credited INTEGER NOT NULL DEFAULT 0,
    refunded INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 0,
    claim_token TEXT,
    claim_until INTEGER NOT NULL DEFAULT 0,
    active_event TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE(principal, context_json, idempotency_key)
);
CREATE TABLE IF NOT EXISTS payment_events (
    event_id TEXT PRIMARY KEY,
    evidence_hash TEXT NOT NULL,
    checkout_id TEXT,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    amount INTEGER NOT NULL DEFAULT 0,
    target_amount INTEGER NOT NULL DEFAULT 0,
    operation_id TEXT,
    revision INTEGER NOT NULL DEFAULT 0,
    claim_token TEXT,
    claim_until INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS payment_velocity (
    principal TEXT NOT NULL,
    utc_day TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 10),
    PRIMARY KEY(principal, utc_day)
);
CREATE TABLE IF NOT EXISTS payment_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checkout_id TEXT,
    event_id TEXT,
    outcome TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS payment_events_checkout ON payment_events(checkout_id, created_at);
