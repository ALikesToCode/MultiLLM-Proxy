-- Default-off text screening. Compare-and-swap revisions protect concurrent dashboard saves.
CREATE TABLE IF NOT EXISTS control_child_safety_settings (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
  failure_mode TEXT NOT NULL DEFAULT 'allow' CHECK(failure_mode IN ('allow', 'block')),
  revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0)
);
INSERT INTO control_child_safety_settings (id) VALUES (1) ON CONFLICT(id) DO NOTHING;
