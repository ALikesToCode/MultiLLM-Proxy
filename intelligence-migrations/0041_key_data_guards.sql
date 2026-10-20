-- Key data controls. Apply before the matching release.
ALTER TABLE control_users ADD COLUMN official_only INTEGER CHECK (official_only IN (0, 1));
ALTER TABLE control_users ADD COLUMN forced_provider_preferences TEXT;
