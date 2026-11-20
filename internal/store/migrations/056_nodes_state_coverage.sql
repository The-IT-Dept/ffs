-- Node-agent state for honest node coverage: when a fresh agent report was first seen since the agent was
-- enabled (the node baseline's settle window starts there), how old a reporting node's last full report
-- may be before its host inventory counts as not current (nanoseconds; 0 is not checked), and the nodes
-- the agent DaemonSet does not schedule on, as a JSON object of node name to why.
ALTER TABLE nodes_state ADD COLUMN first_report_at INTEGER;
ALTER TABLE nodes_state ADD COLUMN full_report_overdue INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes_state ADD COLUMN unsupported TEXT NOT NULL DEFAULT '{}';
