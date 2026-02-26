ALTER TABLE downloads ADD COLUMN email_hash TEXT;

ALTER TABLE contact_messages ADD COLUMN email_hash TEXT;

CREATE TABLE IF NOT EXISTS pageviews (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  path TEXT NOT NULL,
  lang TEXT,
  referrer TEXT,
  ip_hash TEXT NOT NULL,
  user_agent_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_downloads_email_hash ON downloads(email_hash);
CREATE INDEX IF NOT EXISTS idx_contact_email_hash ON contact_messages(email_hash);
CREATE INDEX IF NOT EXISTS idx_pageviews_created_at_ms ON pageviews(created_at_ms);
CREATE INDEX IF NOT EXISTS idx_pageviews_path ON pageviews(path);
CREATE INDEX IF NOT EXISTS idx_pageviews_ip_hash ON pageviews(ip_hash);
