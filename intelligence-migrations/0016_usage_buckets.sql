-- Nullable prompt cache buckets on the 0007 usage ledger; output_tokens already exists.
ALTER TABLE usage_events ADD COLUMN ordinary_input_tokens INTEGER;
ALTER TABLE usage_events ADD COLUMN cache_read_input_tokens INTEGER;
ALTER TABLE usage_events ADD COLUMN cache_write_input_tokens INTEGER;
ALTER TABLE usage_events ADD COLUMN ordinary_input_cost_microusd REAL;
ALTER TABLE usage_events ADD COLUMN cache_read_input_cost_microusd REAL;
ALTER TABLE usage_events ADD COLUMN cache_write_input_cost_microusd REAL;
ALTER TABLE usage_events ADD COLUMN output_cost_microusd REAL;
ALTER TABLE usage_events ADD COLUMN bucket_basis TEXT;
ALTER TABLE usage_events ADD COLUMN bucket_source TEXT;
