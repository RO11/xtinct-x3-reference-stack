PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS v1_card_versions (
  task_id TEXT NOT NULL,
  revision TEXT NOT NULL,
  card_json TEXT NOT NULL CHECK (json_valid(card_json)),
  report_object_key TEXT,
  report_sha256 TEXT,
  report_bytes INTEGER,
  published_at TEXT NOT NULL,
  PRIMARY KEY (task_id, revision),
  CHECK (length(revision) = 32),
  CHECK (
    (report_object_key IS NULL AND report_sha256 IS NULL AND report_bytes IS NULL) OR
    (report_object_key IS NOT NULL AND length(report_sha256) = 64 AND report_bytes BETWEEN 1 AND 24576)
  )
);

CREATE TABLE IF NOT EXISTS v1_cards_current (
  task_id TEXT PRIMARY KEY,
  revision TEXT NOT NULL,
  card_json TEXT NOT NULL CHECK (json_valid(card_json)),
  report_object_key TEXT,
  report_sha256 TEXT,
  report_bytes INTEGER,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (task_id, revision) REFERENCES v1_card_versions(task_id, revision),
  CHECK (length(revision) = 32),
  CHECK (
    (report_object_key IS NULL AND report_sha256 IS NULL AND report_bytes IS NULL) OR
    (report_object_key IS NOT NULL AND length(report_sha256) = 64 AND report_bytes BETWEEN 1 AND 24576)
  )
);

CREATE TABLE IF NOT EXISTS v2_artifacts (
  sha256 TEXT PRIMARY KEY CHECK (length(sha256) = 64),
  object_key TEXT NOT NULL UNIQUE,
  bytes INTEGER NOT NULL CHECK (bytes BETWEEN 1 AND 20971520),
  mime TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('card', 'text', 'image-1bit', 'epub', 'action', 'sleep-screen')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_deliveries (
  item_id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL UNIQUE,
  revision TEXT NOT NULL CHECK (length(revision) = 64),
  delivery_json TEXT NOT NULL CHECK (json_valid(delivery_json)),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_changes (
  cursor INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id TEXT NOT NULL,
  change_type TEXT NOT NULL CHECK (change_type IN ('delivery', 'tombstone')),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json))
);

CREATE INDEX IF NOT EXISTS idx_v2_changes_cursor ON v2_changes(cursor);
CREATE UNIQUE INDEX IF NOT EXISTS idx_v2_changes_item ON v2_changes(item_id);

CREATE TABLE IF NOT EXISTS v2_acks (
  event_id TEXT PRIMARY KEY,
  event_json TEXT NOT NULL CHECK (json_valid(event_json)),
  received_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v2_acks_received ON v2_acks(received_at DESC, event_id DESC);
