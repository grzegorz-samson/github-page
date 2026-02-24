CREATE TABLE IF NOT EXISTS downloads (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT NOT NULL,
  purposes_json TEXT NOT NULL,
  purpose_other TEXT,
  institution TEXT,
  consent_terms INTEGER NOT NULL,
  consent_stats INTEGER NOT NULL,
  consent_updates INTEGER NOT NULL,
  lang TEXT,
  plugin_version TEXT,
  user_agent TEXT,
  ip_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_downloads_created_at_ms ON downloads(created_at_ms);
CREATE INDEX IF NOT EXISTS idx_downloads_email ON downloads(email);
CREATE INDEX IF NOT EXISTS idx_downloads_ip_hash ON downloads(ip_hash);
