-- Asynchronous media jobs: image batches and video webhook watches. The Worker's
-- MediaJobWorkflow drives them, so they survive Container sleep; the Container reaches
-- these rows only through the private media-jobs handler (worker/media-jobs.mjs).
CREATE TABLE IF NOT EXISTS media_jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('image_batch', 'video')),
  owner TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued', 'in_progress', 'cancelling', 'completed', 'cancelled', 'failed', 'expired')),
  principal TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  item_count INTEGER NOT NULL DEFAULT 0,
  webhook_url TEXT,
  webhook_status TEXT CHECK(webhook_status IS NULL OR webhook_status IN ('pending', 'delivered', 'rejected', 'failed')),
  metadata TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata)),
  result TEXT CHECK(result IS NULL OR json_valid(result)),
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  lease_until INTEGER,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  completed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_media_jobs_owner_created ON media_jobs(owner, kind, created_at);
CREATE INDEX IF NOT EXISTS idx_media_jobs_status ON media_jobs(kind, status, lease_until);
CREATE TABLE IF NOT EXISTS media_job_items (
  job_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  custom_id TEXT NOT NULL,
  request TEXT NOT NULL CHECK(json_valid(request)),
  status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  attempt TEXT,
  lease_until INTEGER,
  model TEXT,
  files TEXT CHECK(files IS NULL OR json_valid(files)),
  error TEXT CHECK(error IS NULL OR json_valid(error)),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (job_id, idx)
);
CREATE INDEX IF NOT EXISTS idx_media_job_items_status ON media_job_items(job_id, status, idx);
