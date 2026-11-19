-- Nodes and the control-plane version (Task 6). Times are INTEGER UTC Unix nanoseconds.
CREATE TABLE nodes(name TEXT PRIMARY KEY, os TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL DEFAULT '',
  os_image TEXT NOT NULL DEFAULT '', kernel_version TEXT NOT NULL DEFAULT '', kubelet_version TEXT NOT NULL DEFAULT '',
  container_runtime_version TEXT NOT NULL DEFAULT '', ready INTEGER NOT NULL DEFAULT 0, updated_at INTEGER);
CREATE TABLE cluster_info(id INTEGER PRIMARY KEY CHECK (id = 1), name TEXT NOT NULL DEFAULT '', git_version TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '', distribution TEXT NOT NULL DEFAULT '', low_confidence INTEGER NOT NULL DEFAULT 0,
  kube_proxy_version TEXT NOT NULL DEFAULT '', updated_at INTEGER);
