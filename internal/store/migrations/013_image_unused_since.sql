-- When PruneImages first found each image unused: run by no owner and held by no upgrade suggestion
-- (F30). Superseded rollout digests were kept until resolved-finding retention (90 days) with their
-- SBOMs, packages, matches and grype keys, which fills the PVC and the weekly re-match on busy
-- clusters. PruneImages marks unused images, clears the mark when one is used again, and deletes
-- those unused for a week. NULL means in use, or not yet seen unused.
ALTER TABLE images ADD COLUMN unused_since INTEGER;
