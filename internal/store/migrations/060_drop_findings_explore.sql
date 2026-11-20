-- The findings explorer's counts and facets read findings_groups (055), which holds every column of
-- findings_explore (050) and serves the group and page statements already. Every finding write kept
-- both up to date, so findings_explore goes.
DROP INDEX findings_explore;
