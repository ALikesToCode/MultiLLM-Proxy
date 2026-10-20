-- Integration credentials use the same explicit data controls as account keys.
ALTER TABLE intelligence_principals ADD COLUMN official_only INTEGER CHECK (official_only IS NULL OR official_only IN (0, 1));
ALTER TABLE intelligence_principals ADD COLUMN forced_provider_preferences TEXT;
