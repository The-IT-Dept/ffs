-- Node agent state, one row per node whose agent has reported: the last applied report's identity
-- (boot ID, process start, sequence), its times, the host fields of the last full report, the host
-- fingerprint whose SBOM is stored and the agent group the node belongs to.
CREATE TABLE nodes_agent (node TEXT PRIMARY KEY, agent_version TEXT NOT NULL DEFAULT '', boot_id TEXT NOT NULL DEFAULT '',
  started_at INTEGER, seq INTEGER NOT NULL DEFAULT 0, last_report INTEGER, last_full_report INTEGER,
  last_error TEXT NOT NULL DEFAULT '', kernel_release TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL DEFAULT '',
  package_db TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '', group_id TEXT NOT NULL DEFAULT '',
  reboot_pending INTEGER NOT NULL DEFAULT 0, reboot_reason TEXT NOT NULL DEFAULT '',
  coverage TEXT NOT NULL DEFAULT '[]', problems TEXT NOT NULL DEFAULT '[]');
