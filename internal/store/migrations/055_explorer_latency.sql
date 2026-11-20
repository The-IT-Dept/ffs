-- Read paths the web UI's API latency gate (25,000 open findings, 300 workloads) found slow.
--
-- owner_entities: without table statistics the planner drove the effective-privilege EXISTS from the
-- images table, parsing an owner's containers once per catalogued image. CROSS JOIN keeps the
-- owner's containers as the outer loop and finds each image by its key. Same columns and meaning.
DROP VIEW owner_entities;
CREATE VIEW owner_entities AS SELECT o.key, o.namespace, o.kind, o.name, o.exposed, o.sa_power, o.not_running, o.managed_by,
  (o.ctx_privileged OR EXISTS (SELECT 1 FROM json_each(o.data, '$.Containers') c CROSS JOIN images i ON i.digest = json_extract(c.value, '$.Digest')
     WHERE json_extract(c.value, '$.RootUnlessImageUser') AND i.status = 'catalogued'
       AND substr(i.config_user, 1, instr(i.config_user || ':', ':') - 1) IN ('', '0', 'root'))) AS privileged
  FROM owners o;
-- Finding groups and findings pages over the cluster, a namespace or the control plane read every
-- column they filter, group or sort on from this index instead of each finding's JSON:
-- findings_explore's columns plus fix_key, image_repo, epss, published and fingerprint. A page ranks
-- on the index and reads only its own rows. fix_key leads after state, so fix groups come in order.
CREATE INDEX findings_groups ON findings(state, fix_key, priority, image_repo, fix_class, ecosystem, owner_kind, namespace, signals,
  severity, fix_available, owner_key, advisory_id, epss, published, fingerprint);
-- The packages explorer groups the packages of the in-use digests in this index's order, and counts a
-- page's workloads from it, without reading a package row.
CREATE INDEX packages_explore ON packages(ecosystem, name, version, epoch, digest, classifier);
