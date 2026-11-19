-- Notification state (Task 25). notified is the never-twice ledger: the highest priority already
-- sent to a target for a finding, and the state it was last notified in. deliveries is the outbox
-- and delivery log; a row's id is the message id, so re-enqueueing the same message is a no-op.
-- notify_targets holds each AlertTarget's baseline, digest and delivery status, keyed by its UID.
CREATE TABLE notified (target TEXT NOT NULL, fingerprint TEXT NOT NULL, max_priority INTEGER NOT NULL,
  last_state TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (target, fingerprint));
CREATE TABLE deliveries (id TEXT PRIMARY KEY, target TEXT NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL,
  state TEXT NOT NULL, not_before INTEGER NOT NULL, next_attempt INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '', http_status INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, sent_at INTEGER);
CREATE INDEX deliveries_pending ON deliveries(state, next_attempt, not_before);
CREATE INDEX deliveries_target ON deliveries(target, created_at);
CREATE TABLE notify_targets (target TEXT PRIMARY KEY, name TEXT NOT NULL, config_hash TEXT NOT NULL DEFAULT '',
  baseline_at INTEGER, last_digest_at INTEGER, last_delivery_at INTEGER, last_error TEXT NOT NULL DEFAULT '',
  consecutive_failures INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0, disabled_reason TEXT NOT NULL DEFAULT '');
