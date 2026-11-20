-- The owner and namespace of each transition, generated from its JSON, so the web UI reads the
-- history of a workload, namespace or the control plane through an index.
ALTER TABLE transitions ADD COLUMN owner_key TEXT GENERATED ALWAYS AS (json_extract(data, '$.Owner.Kind') || '/' ||
  coalesce(json_extract(data, '$.Owner.Namespace'), '') || '/' || json_extract(data, '$.Owner.Name')) VIRTUAL;
ALTER TABLE transitions ADD COLUMN namespace TEXT GENERATED ALWAYS AS (coalesce(json_extract(data, '$.Owner.Namespace'), '')) VIRTUAL;
CREATE INDEX transitions_owner ON transitions(owner_key, id);
CREATE INDEX transitions_namespace ON transitions(namespace, id);
