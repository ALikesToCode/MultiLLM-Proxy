CREATE TABLE IF NOT EXISTS gateway_batch_files (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, filename TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('batch', 'batch_output')),
  bytes INTEGER NOT NULL, r2_key TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS gateway_batch_files_owner ON gateway_batch_files(owner, created_at, id);
CREATE TABLE IF NOT EXISTS gateway_batches (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, input_file_id TEXT NOT NULL,
  endpoint TEXT NOT NULL, status TEXT NOT NULL, metadata TEXT NOT NULL,
  principal TEXT NOT NULL, client_ip TEXT NOT NULL, key_hash TEXT NOT NULL, key_prefix TEXT NOT NULL,
  budget_units INTEGER NOT NULL CHECK (budget_units > 0), created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  in_progress_at INTEGER, finalizing_at INTEGER, completed_at INTEGER,
  cancelling_at INTEGER, cancelled_at INTEGER, expired_at INTEGER, failed_at INTEGER,
  output_file_id TEXT, error_file_id TEXT, terminal_status TEXT,
  finalize_cursor INTEGER NOT NULL DEFAULT 0, checkpoint TEXT,
  lease_token TEXT, lease_until INTEGER
);
CREATE INDEX IF NOT EXISTS gateway_batches_owner ON gateway_batches(owner, created_at, id);
CREATE INDEX IF NOT EXISTS gateway_batches_active ON gateway_batches(status, expires_at);
CREATE TABLE IF NOT EXISTS gateway_batch_items (
  batch_id TEXT NOT NULL REFERENCES gateway_batches(id), idx INTEGER NOT NULL,
  owner TEXT NOT NULL, custom_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
  estimate_units INTEGER NOT NULL CHECK (estimate_units >= 0),
  held_units INTEGER NOT NULL DEFAULT 0 CHECK (held_units >= 0),
  cost_units INTEGER NOT NULL DEFAULT 0 CHECK (cost_units >= 0),
  result_key TEXT, error_code TEXT, lease_token TEXT, lease_until INTEGER,
  PRIMARY KEY (batch_id, idx), UNIQUE (batch_id, custom_id)
);
CREATE INDEX IF NOT EXISTS gateway_batch_items_claim ON gateway_batch_items(status, batch_id, idx);
