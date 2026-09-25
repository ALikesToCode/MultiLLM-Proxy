-- Operator-edited automatic routes. Container disk is reset on sleep and replacement, so
-- routes live here; seeded defaults apply to any route without a stored row.
CREATE TABLE IF NOT EXISTS auto_routes (
  route_id TEXT PRIMARY KEY,
  candidates TEXT NOT NULL CHECK(json_valid(candidates) AND json_type(candidates) = 'array'),
  updated_at TEXT NOT NULL
);
