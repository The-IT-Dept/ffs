-- Owner columns and views for the web UI's workload explorer and exposure view, generated from each
-- owner's JSON. Exposure edges are read from the owner row itself, so they cannot drift from it.
ALTER TABLE owners ADD COLUMN kind TEXT GENERATED ALWAYS AS (substr(key, 1, instr(key, '/') - 1)) VIRTUAL;
ALTER TABLE owners ADD COLUMN name TEXT GENERATED ALWAYS AS (json_extract(data, '$.Ref.Name')) VIRTUAL;
ALTER TABLE owners ADD COLUMN exposed INTEGER GENERATED ALWAYS AS (coalesce(json_extract(data, '$.Context.Exposed'), 0)) VIRTUAL;
ALTER TABLE owners ADD COLUMN ctx_privileged INTEGER GENERATED ALWAYS AS (coalesce(json_extract(data, '$.Context.Privileged'), 0)) VIRTUAL;
ALTER TABLE owners ADD COLUMN sa_power INTEGER GENERATED ALWAYS AS (coalesce(json_extract(data, '$.Context.PowerfulSA'), 0)) VIRTUAL;
ALTER TABLE owners ADD COLUMN not_running INTEGER GENERATED ALWAYS AS (coalesce(json_extract(data, '$.NotRunning'), 0)) VIRTUAL;
ALTER TABLE owners ADD COLUMN managed_by TEXT GENERATED ALWAYS AS (coalesce(json_extract(data, '$.ManagedBy.Tool'), '')) VIRTUAL;
CREATE INDEX owners_namespace_kind ON owners(namespace, kind, name);
-- Effective privilege = context privilege OR a container that runs as its image's user on a catalogued image whose config user
-- is root (the rule of findings.ownerContext / rootUser).
CREATE VIEW owner_entities AS SELECT o.key, o.namespace, o.kind, o.name, o.exposed, o.sa_power, o.not_running, o.managed_by,
  (o.ctx_privileged OR EXISTS (SELECT 1 FROM json_each(o.data, '$.Containers') c JOIN images i ON i.digest = json_extract(c.value, '$.Digest')
     WHERE json_extract(c.value, '$.RootUnlessImageUser') AND i.status = 'catalogued'
       AND substr(i.config_user, 1, instr(i.config_user || ':', ':') - 1) IN ('', '0', 'root'))) AS privileged
  FROM owners o;
CREATE VIEW exposure_edges AS SELECT o.key AS owner_key, o.namespace AS namespace,
  json_extract(e.value, '$.Entry') AS entry, json_extract(e.value, '$.EntryName') AS entry_name,
  json_extract(e.value, '$.Listener') AS listener, json_extract(e.value, '$.Hostname') AS hostname,
  json_extract(e.value, '$.Route') AS route, json_extract(e.value, '$.Service') AS service,
  json_extract(e.value, '$.Internal') AS internal
  FROM owners o, json_each(o.data, '$.Context.Exposure') e
  WHERE e.type = 'object'; -- an owner with no edges stores null, which json_each returns as one row
