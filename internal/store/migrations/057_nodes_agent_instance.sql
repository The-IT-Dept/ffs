-- The agent process (a random instance ID per start) of a node's last applied report. Reports are ordered
-- by (boot ID, instance, sequence): the wall-clock process start can step back and no longer orders them.
ALTER TABLE nodes_agent ADD COLUMN instance TEXT NOT NULL DEFAULT '';
