-- Images cached on each node, from the agent's content-store scan and node.status.images, and
-- whether a pod on the node runs them.
CREATE TABLE node_images (node TEXT NOT NULL, digest TEXT NOT NULL, config_digest TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'manifest', names TEXT NOT NULL DEFAULT '[]', size_bytes INTEGER NOT NULL DEFAULT 0,
  complete INTEGER NOT NULL DEFAULT 0, in_use INTEGER NOT NULL DEFAULT 0, source TEXT NOT NULL,  -- 'content-store'|'status'|'both'
  PRIMARY KEY (node, digest));
CREATE INDEX node_images_digest ON node_images(digest);
CREATE INDEX node_images_config ON node_images(config_digest);
