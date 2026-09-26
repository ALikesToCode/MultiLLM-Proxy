-- Per-key controls. NULL keeps the previous behavior: no dollar budget, every model,
-- no expiry and every client address. Lists are comma-separated.
ALTER TABLE control_users ADD COLUMN daily_budget_usd REAL CHECK(daily_budget_usd IS NULL OR daily_budget_usd >= 0);
ALTER TABLE control_users ADD COLUMN monthly_budget_usd REAL CHECK(monthly_budget_usd IS NULL OR monthly_budget_usd >= 0);
ALTER TABLE control_users ADD COLUMN allowed_models TEXT;
ALTER TABLE control_users ADD COLUMN allowed_ips TEXT;
ALTER TABLE control_users ADD COLUMN expires_at TEXT;

-- One row per billable request (chat, responses, images, videos, embeddings, audio and
-- provider pass-through). No prompts, outputs or keys: only the key prefix. Raw rows are
-- pruned after the configured retention; usage_daily keeps the totals.
CREATE TABLE IF NOT EXISTS usage_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  day TEXT NOT NULL,
  principal TEXT NOT NULL,
  key_prefix TEXT,
  kind TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  requested_model TEXT,
  selected_model TEXT,
  status INTEGER NOT NULL CHECK(status BETWEEN 100 AND 599),
  latency_ms INTEGER NOT NULL CHECK(latency_ms >= 0),
  input_tokens INTEGER CHECK(input_tokens IS NULL OR input_tokens >= 0),
  output_tokens INTEGER CHECK(output_tokens IS NULL OR output_tokens >= 0),
  cost_usd REAL CHECK(cost_usd IS NULL OR cost_usd >= 0),
  cost_basis TEXT CHECK(cost_basis IS NULL OR cost_basis IN ('usage', 'estimate')),
  request_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_usage_events_at ON usage_events(at);
CREATE INDEX IF NOT EXISTS idx_usage_events_principal ON usage_events(principal, id);

-- Daily totals per key and selected model, written with every flush. Budgets and the
-- usage dashboard read these. Latency is a histogram of per-bucket counts, so p50 and
-- p95 can be estimated for any range of days.
CREATE TABLE IF NOT EXISTS usage_daily (
  day TEXT NOT NULL,
  principal TEXT NOT NULL,
  model TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cost_usd REAL NOT NULL DEFAULT 0,
  priced_requests INTEGER NOT NULL DEFAULT 0,
  latency_ms_total INTEGER NOT NULL DEFAULT 0,
  lat_le_250 INTEGER NOT NULL DEFAULT 0,
  lat_le_500 INTEGER NOT NULL DEFAULT 0,
  lat_le_1000 INTEGER NOT NULL DEFAULT 0,
  lat_le_2000 INTEGER NOT NULL DEFAULT 0,
  lat_le_4000 INTEGER NOT NULL DEFAULT 0,
  lat_le_8000 INTEGER NOT NULL DEFAULT 0,
  lat_le_15000 INTEGER NOT NULL DEFAULT 0,
  lat_le_30000 INTEGER NOT NULL DEFAULT 0,
  lat_le_60000 INTEGER NOT NULL DEFAULT 0,
  lat_le_120000 INTEGER NOT NULL DEFAULT 0,
  lat_gt_120000 INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, principal, model)
);
CREATE INDEX IF NOT EXISTS idx_usage_daily_principal ON usage_daily(principal, day);

-- Flush batches already applied, so a retried flush whose first reply was lost is not
-- counted twice. Pruned with the raw rows.
CREATE TABLE IF NOT EXISTS usage_batches (
  id TEXT PRIMARY KEY,
  token TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_batches_at ON usage_batches(at);
