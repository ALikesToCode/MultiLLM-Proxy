-- Provider-reported usage details; old event rows keep unknown values.
ALTER TABLE usage_events ADD COLUMN cached_input_tokens INTEGER CHECK (cached_input_tokens >= 0);
ALTER TABLE usage_events ADD COLUMN reasoning_tokens INTEGER CHECK (reasoning_tokens >= 0);
ALTER TABLE usage_daily ADD COLUMN cached_input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cached_input_tokens >= 0);
ALTER TABLE usage_daily ADD COLUMN reasoning_tokens INTEGER NOT NULL DEFAULT 0 CHECK (reasoning_tokens >= 0);
