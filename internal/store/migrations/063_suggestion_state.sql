-- Upgrade suggestions keep what a restart used to lose (v0.0.2). stale marks a suggestion that scored a
-- candidate whose matches changed: it stays until the owner is resolved again, and a restart queues
-- its owner. applied is the upgrade the owner moved to (JSON store.AppliedUpgrade, NULL for none), so
-- "upgrade applied, still affected" lasts while an advisory it was to fix stays open.
ALTER TABLE suggestions ADD COLUMN stale INTEGER NOT NULL DEFAULT 0;
ALTER TABLE suggestions ADD COLUMN applied TEXT;
