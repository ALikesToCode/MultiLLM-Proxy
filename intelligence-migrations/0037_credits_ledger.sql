CREATE TABLE IF NOT EXISTS credits_balances (
    owner TEXT PRIMARY KEY,
    balance_microusd INTEGER NOT NULL DEFAULT 0 CHECK (balance_microusd BETWEEN -1000000000000000 AND 1000000000000000),
    held_microusd INTEGER NOT NULL DEFAULT 0 CHECK (held_microusd BETWEEN 0 AND 1000000000000000),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 1000000000000000)
);
CREATE TABLE IF NOT EXISTS credits_entries (
    owner TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('credit','reserve','commit','release','adjust','compensate')),
    amount_microusd INTEGER NOT NULL CHECK (amount_microusd BETWEEN -1000000000000000 AND 1000000000000000),
    balance_delta INTEGER NOT NULL,
    held_delta INTEGER NOT NULL,
    scoped_id TEXT,
    reference TEXT,
    tariff_revision INTEGER,
    actor TEXT,
    reason TEXT,
    document TEXT NOT NULL,
    PRIMARY KEY (owner, operation_id),
    UNIQUE (owner, revision)
);
CREATE UNIQUE INDEX IF NOT EXISTS credits_compensation_once ON credits_entries(owner, reference) WHERE kind = 'compensate';
CREATE INDEX IF NOT EXISTS credits_attempt_entries ON credits_entries(owner, scoped_id, revision);
CREATE TABLE IF NOT EXISTS credits_audit (
    owner TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    actor TEXT NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY (owner, operation_id)
);
