-- The single node-agent state row: whether the agent is enabled, whether the ContainerRuntime owner
-- is retired, since when not every node is fresh, the last cutover and when the node baseline was ready.
CREATE TABLE nodes_state (id INTEGER PRIMARY KEY CHECK (id = 1), agent_enabled INTEGER NOT NULL DEFAULT 0,
  runtime_retired INTEGER NOT NULL DEFAULT 0, not_fresh_since INTEGER, changed_at INTEGER, baseline_ready_at INTEGER);
