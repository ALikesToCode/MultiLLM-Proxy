-- Page bodies live only in the context-pages/ prefix of multillm_media.
CREATE TABLE IF NOT EXISTS context_pages (
    page_id TEXT PRIMARY KEY,
    principal TEXT NOT NULL,
    session_hash TEXT NOT NULL,
    revision TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_length INTEGER NOT NULL CHECK (byte_length > 0 AND byte_length <= 65536),
    expires_at INTEGER NOT NULL,
    r2_key TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS context_pages_session_expiry
    ON context_pages (principal, session_hash, expires_at);
