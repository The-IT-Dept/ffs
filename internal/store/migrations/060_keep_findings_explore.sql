-- v0.0.2 keeps findings_explore (050) although its explorer reads findings_groups (055) instead:
-- v0.0.1 names findings_explore in its counts and facets, so dropping it would break v0.0.1's
-- Findings page after a rollback on the same volume. The drop is deferred to v0.0.3.
-- This migration's unreleased first form (060_drop_findings_explore.sql) dropped the index; a store
-- that ran it gets the index back here.
CREATE INDEX IF NOT EXISTS findings_explore ON findings(state, priority, fix_class, ecosystem, owner_kind, namespace, signals,
  severity, fix_available, owner_key, advisory_id);
