-- When each AlertTarget got its node inventory baseline (one summary of the open node findings).
-- Node findings are held from a target's immediate alerts and digests until then.
ALTER TABLE notify_targets ADD COLUMN nodes_baseline_at INTEGER;
