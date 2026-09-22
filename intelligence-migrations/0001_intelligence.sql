CREATE TABLE IF NOT EXISTS intelligence_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    document TEXT NOT NULL CHECK (json_valid(document))
);

CREATE TABLE IF NOT EXISTS intelligence_reservations (
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    principal TEXT NOT NULL CHECK (length(principal) BETWEEN 1 AND 256),
    kind TEXT NOT NULL CHECK (kind IN ('chat', 'transcriptions', 'speech', 'embeddings')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    reserved INTEGER NOT NULL CHECK (reserved BETWEEN 1 AND 9007199254740991),
    charged INTEGER NOT NULL CHECK (charged BETWEEN 0 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('pending', 'unknown', 'settled'))
);

CREATE INDEX IF NOT EXISTS idx_intelligence_allowance
    ON intelligence_reservations(kind, created_at, principal);
CREATE INDEX IF NOT EXISTS idx_intelligence_pending
    ON intelligence_reservations(kind, state);
