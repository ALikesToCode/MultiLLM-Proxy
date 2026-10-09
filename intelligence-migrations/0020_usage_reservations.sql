CREATE TABLE IF NOT EXISTS usage_reservation_budgets (
    principal TEXT NOT NULL,
    period TEXT NOT NULL,
    baseline_units INTEGER NOT NULL CHECK (baseline_units >= 0),
    PRIMARY KEY (principal, period)
);
CREATE TABLE IF NOT EXISTS usage_reservations (
    id TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    day TEXT NOT NULL,
    month TEXT NOT NULL,
    amount_units INTEGER NOT NULL CHECK (amount_units >= 0),
    charged_units INTEGER,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'dispatched', 'settled', 'unknown', 'reconciled')),
    basis TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    handoff_at INTEGER,
    revision INTEGER NOT NULL DEFAULT 0,
    transition_id TEXT NOT NULL,
    settlement_id TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS usage_reservations_principal ON usage_reservations (principal, state, day, month);
CREATE TABLE IF NOT EXISTS usage_reservation_transitions (
    transition_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL REFERENCES usage_reservations(id),
    previous_state TEXT,
    state TEXT NOT NULL,
    at INTEGER NOT NULL,
    basis TEXT,
    evidence TEXT,
    reason TEXT,
    document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_reservation_transitions_history ON usage_reservation_transitions (reservation_id, at);
