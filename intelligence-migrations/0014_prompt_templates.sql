-- Published versions belong to one principal and are never updated in place.
CREATE TABLE IF NOT EXISTS prompt_templates (
    principal TEXT NOT NULL,
    slug TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    content TEXT NOT NULL,
    variables TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (principal, slug, version)
);
CREATE INDEX IF NOT EXISTS prompt_templates_created ON prompt_templates (principal, created_at);
