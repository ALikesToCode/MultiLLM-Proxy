-- Recent health of automatic-route candidates and providers. The Container keeps the live
-- figures in memory and writes changed rows here in batches, so a restart or another
-- instance starts from the last known health. An older row never replaces a newer one.
CREATE TABLE IF NOT EXISTS route_health (
  target TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK(json_valid(state) AND json_type(state) = 'object'),
  updated_at TEXT NOT NULL
);
-- The public status document. The Worker serves /status and /status.json from this row, so
-- a visit never wakes a sleeping Container.
CREATE TABLE IF NOT EXISTS route_health_snapshot (
  id TEXT PRIMARY KEY CHECK(id = 'public'),
  body TEXT NOT NULL CHECK(json_valid(body) AND json_type(body) = 'object'),
  updated_at TEXT NOT NULL
);
