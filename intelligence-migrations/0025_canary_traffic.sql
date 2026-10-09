-- Reviewed route metadata only. Assignments retain no session or principal.
CREATE TABLE IF NOT EXISTS canary_traffic (
    route_id TEXT PRIMARY KEY,
    route_updated_at TEXT NOT NULL,
    configuration TEXT NOT NULL
);
