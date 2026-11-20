-- Node groups (agent groups keyed by host fingerprint, nodeinfo fallback groups) and the group each
-- node belongs to. Members live in node_group_members only, never in the data JSON.
CREATE TABLE node_groups (id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL, digest TEXT NOT NULL DEFAULT '',
  data TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);   -- data: model.NodeGroup JSON without Members
CREATE TABLE node_group_members (node TEXT PRIMARY KEY, group_id TEXT NOT NULL);
CREATE INDEX node_group_members_group ON node_group_members(group_id);
