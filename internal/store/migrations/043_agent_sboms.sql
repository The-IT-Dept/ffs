-- Provenance of SBOMs catalogued by a node agent (which node and agent version sent each), and the
-- per-digest poison-pill bookkeeping of agent work, kept apart from the registry acquirer's.
CREATE TABLE agent_sboms (digest TEXT PRIMARY KEY, node TEXT NOT NULL, agent_version TEXT NOT NULL, received_at INTEGER NOT NULL);
CREATE TABLE agent_jobs (digest TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
  last_node TEXT NOT NULL DEFAULT '', last_attempt INTEGER, quarantined_until INTEGER);
