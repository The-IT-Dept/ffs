-- Filter and sort columns for the web UI's findings explorer, generated from each finding's JSON so
-- every write path keeps them current; the indexes let facets and pages read them without the row.
ALTER TABLE findings ADD COLUMN owner_kind TEXT GENERATED ALWAYS AS (substr(owner_key, 1, instr(owner_key, '/') - 1)) VIRTUAL;
ALTER TABLE findings ADD COLUMN image_repo TEXT GENERATED ALWAYS AS (json_extract(data, '$.ImageRepo')) VIRTUAL;
ALTER TABLE findings ADD COLUMN ecosystem TEXT GENERATED ALWAYS AS (coalesce(json_extract(data, '$.Packages[0].Ecosystem'), '')) VIRTUAL;
ALTER TABLE findings ADD COLUMN severity INTEGER GENERATED ALWAYS AS (CASE json_extract(data, '$.Severity')
  WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'negligible' THEN 1 ELSE 0 END) VIRTUAL;
ALTER TABLE findings ADD COLUMN fix_available INTEGER GENERATED ALWAYS AS (coalesce(json_extract(data, '$.FixAvailable'), 0)) VIRTUAL;
ALTER TABLE findings ADD COLUMN fix_class TEXT GENERATED ALWAYS AS (CASE
    WHEN json_extract(data, '$.Suggestion') IS NOT NULL THEN 'upgrade'
    WHEN json_extract(data, '$.FixAvailable') THEN 'fixed'
    WHEN json_extract(data, '$.FixState') = 'wont-fix' THEN 'wontfix' ELSE 'none' END) VIRTUAL;
ALTER TABLE findings ADD COLUMN fix_key TEXT GENERATED ALWAYS AS (CASE
    WHEN json_extract(data, '$.Suggestion') IS NOT NULL
      THEN 'upgrade:' || json_extract(data, '$.ImageRepo') || ':' || coalesce(json_extract(data, '$.Suggestion.ToTag'), '')
    ELSE coalesce(json_extract(data, '$.Fix.Key'), CASE WHEN json_extract(data, '$.FixState') = 'wont-fix' THEN 'wontfix' ELSE 'none' END) END) VIRTUAL;
ALTER TABLE findings ADD COLUMN signals INTEGER GENERATED ALWAYS AS (
      coalesce(json_extract(data, '$.Signals.Exposed'), 0)
    | (coalesce(json_extract(data, '$.Signals.Privileged'), 0) << 1)
    | (coalesce(json_extract(data, '$.Signals.PowerfulSA'), 0) << 2)
    | (coalesce(json_extract(data, '$.Signals.KEV'), 0) << 3)
    | (coalesce(json_extract(data, '$.Signals.Malicious'), 0) << 4)
    | (coalesce(json_extract(data, '$.Provisional'), 0) << 5)
    | (coalesce(json_extract(data, '$.Signals.NotRunning'), 0) << 6)
    | (coalesce(json_extract(data, '$.Signals.EPSSElevated'), 0) << 7)) VIRTUAL;
ALTER TABLE findings ADD COLUMN epss REAL GENERATED ALWAYS AS (coalesce(json_extract(data, '$.Signals.EPSS'), 0)) VIRTUAL;
ALTER TABLE findings ADD COLUMN published TEXT GENERATED ALWAYS AS (coalesce(strftime('%Y-%m-%dT%H:%M:%fZ', json_extract(data, '$.Published')), '')) VIRTUAL;
CREATE INDEX findings_explore ON findings(state, priority, fix_class, ecosystem, owner_kind, namespace, signals, severity, fix_available, owner_key, advisory_id);
CREATE INDEX findings_page ON findings(state, priority DESC, advisory_id, fingerprint);
CREATE INDEX findings_resolved ON findings(state, resolved_at);
CREATE INDEX findings_fix ON findings(state, owner_key, fix_key, priority);
