CREATE TABLE IF NOT EXISTS contact_messages (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  name TEXT,
  email TEXT NOT NULL,
  subject TEXT,
  message TEXT NOT NULL,
  lang TEXT,
  source_path TEXT,
  user_agent TEXT,
  ip_hash TEXT NOT NULL,
  email_sent INTEGER NOT NULL DEFAULT 0,
  email_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_contact_created_at_ms ON contact_messages(created_at_ms);
CREATE INDEX IF NOT EXISTS idx_contact_email ON contact_messages(email);
CREATE INDEX IF NOT EXISTS idx_contact_ip_hash ON contact_messages(ip_hash);
