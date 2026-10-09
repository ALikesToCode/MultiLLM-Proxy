-- NULL disables stream cost enforcement for existing keys.
ALTER TABLE control_users ADD COLUMN max_stream_cost_microusd INTEGER CHECK (max_stream_cost_microusd BETWEEN 0 AND 1000000000000);
