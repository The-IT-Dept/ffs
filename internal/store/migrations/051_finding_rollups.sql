-- Rollups of findings by owner, image digest and package for the web UI's counts and facets. Triggers on
-- findings keep them in the writing transaction, whatever the write path (recursive_triggers must be on).
CREATE TABLE owner_stats(owner_key TEXT PRIMARY KEY, namespace TEXT NOT NULL, owner_kind TEXT NOT NULL,
  urgent INTEGER NOT NULL DEFAULT 0, high INTEGER NOT NULL DEFAULT 0, medium INTEGER NOT NULL DEFAULT 0, low INTEGER NOT NULL DEFAULT 0,
  open INTEGER NOT NULL DEFAULT 0, fixable INTEGER NOT NULL DEFAULT 0, upgradable INTEGER NOT NULL DEFAULT 0,
  exploited INTEGER NOT NULL DEFAULT 0, provisional INTEGER NOT NULL DEFAULT 0, excepted INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE INDEX owner_stats_namespace ON owner_stats(namespace);
CREATE TABLE finding_digests(digest TEXT NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL, priority INTEGER NOT NULL,
  fix_available INTEGER NOT NULL, PRIMARY KEY(digest, fingerprint)) WITHOUT ROWID;
CREATE INDEX finding_digests_fp ON finding_digests(fingerprint);
CREATE TABLE finding_packages(ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, fingerprint TEXT NOT NULL,
  state TEXT NOT NULL, priority INTEGER NOT NULL, fix_available INTEGER NOT NULL, PRIMARY KEY(ecosystem, name, version, fingerprint)) WITHOUT ROWID;
CREATE INDEX finding_packages_fp ON finding_packages(fingerprint);
CREATE INDEX finding_packages_state ON finding_packages(state, ecosystem, name, version, priority);

-- Fill from the findings stored before this migration, with the contributions the triggers use. A finding
-- with no digests or packages stores null, which json_each returns as one row; the type filters skip it.
INSERT INTO owner_stats(owner_key, namespace, owner_kind, urgent, high, medium, low, open, fixable, upgradable, exploited, provisional, excepted)
SELECT f.owner_key, min(f.namespace), min(f.owner_kind),
  sum(f.state = 'open' AND f.priority = 4),
  sum(f.state = 'open' AND f.priority = 3),
  sum(f.state = 'open' AND f.priority = 2),
  sum(f.state = 'open' AND f.priority = 1),
  sum(f.state = 'open'),
  sum(f.state = 'open' AND f.fix_available),
  sum(f.state = 'open' AND f.fix_class = 'upgrade'),
  sum(f.state = 'open' AND f.signals & 8 != 0),
  sum(f.state = 'open' AND f.signals & 32 != 0),
  sum(f.state = 'excepted')
FROM findings f WHERE f.state IN ('open', 'excepted') GROUP BY f.owner_key;
INSERT INTO finding_digests(digest, fingerprint, state, priority, fix_available)
SELECT DISTINCT d.value, f.fingerprint, f.state, f.priority, f.fix_available FROM findings f, json_each(f.data, '$.Digests') d WHERE d.type = 'text';
INSERT INTO finding_packages(ecosystem, name, version, fingerprint, state, priority, fix_available)
SELECT DISTINCT coalesce(json_extract(p.value, '$.Ecosystem'), ''), coalesce(json_extract(p.value, '$.Name'), ''),
  coalesce(json_extract(p.value, '$.Installed'), ''), f.fingerprint, f.state, f.priority, f.fix_available
FROM findings f, json_each(f.data, '$.Packages') p WHERE p.type = 'object';

-- Owner contributions: urgent, high, medium and low count open findings at priority 4, 3, 2 and 1; open counts open
-- findings; fixable those with a fixed version; upgradable those with a Suggestion; exploited those listed in KEV
-- (signals bit 8); provisional those with signals bit 32; excepted counts excepted findings.
CREATE TRIGGER findings_rollup_insert AFTER INSERT ON findings BEGIN
  INSERT INTO owner_stats(owner_key, namespace, owner_kind, urgent, high, medium, low, open, fixable, upgradable, exploited, provisional, excepted)
    SELECT NEW.owner_key, NEW.namespace, NEW.owner_kind,
      NEW.state = 'open' AND NEW.priority = 4,
      NEW.state = 'open' AND NEW.priority = 3,
      NEW.state = 'open' AND NEW.priority = 2,
      NEW.state = 'open' AND NEW.priority = 1,
      NEW.state = 'open',
      NEW.state = 'open' AND NEW.fix_available,
      NEW.state = 'open' AND NEW.fix_class = 'upgrade',
      NEW.state = 'open' AND NEW.signals & 8 != 0,
      NEW.state = 'open' AND NEW.signals & 32 != 0,
      NEW.state = 'excepted'
    WHERE NEW.state IN ('open', 'excepted')
    ON CONFLICT(owner_key) DO UPDATE SET
      urgent = urgent + excluded.urgent,
      high = high + excluded.high,
      medium = medium + excluded.medium,
      low = low + excluded.low,
      open = open + excluded.open,
      fixable = fixable + excluded.fixable,
      upgradable = upgradable + excluded.upgradable,
      exploited = exploited + excluded.exploited,
      provisional = provisional + excluded.provisional,
      excepted = excepted + excluded.excepted;
  INSERT INTO finding_digests(digest, fingerprint, state, priority, fix_available)
    SELECT DISTINCT d.value, NEW.fingerprint, NEW.state, NEW.priority, NEW.fix_available FROM json_each(NEW.data, '$.Digests') d WHERE d.type = 'text';
  INSERT INTO finding_packages(ecosystem, name, version, fingerprint, state, priority, fix_available)
    SELECT DISTINCT coalesce(json_extract(p.value, '$.Ecosystem'), ''), coalesce(json_extract(p.value, '$.Name'), ''),
      coalesce(json_extract(p.value, '$.Installed'), ''), NEW.fingerprint, NEW.state, NEW.priority, NEW.fix_available
    FROM json_each(NEW.data, '$.Packages') p WHERE p.type = 'object';
END;
CREATE TRIGGER findings_rollup_delete AFTER DELETE ON findings BEGIN
  UPDATE owner_stats SET
      urgent = urgent - (OLD.state = 'open' AND OLD.priority = 4),
      high = high - (OLD.state = 'open' AND OLD.priority = 3),
      medium = medium - (OLD.state = 'open' AND OLD.priority = 2),
      low = low - (OLD.state = 'open' AND OLD.priority = 1),
      open = open - (OLD.state = 'open'),
      fixable = fixable - (OLD.state = 'open' AND OLD.fix_available),
      upgradable = upgradable - (OLD.state = 'open' AND OLD.fix_class = 'upgrade'),
      exploited = exploited - (OLD.state = 'open' AND OLD.signals & 8 != 0),
      provisional = provisional - (OLD.state = 'open' AND OLD.signals & 32 != 0),
      excepted = excepted - (OLD.state = 'excepted')
    WHERE owner_key = OLD.owner_key AND OLD.state IN ('open', 'excepted');
  DELETE FROM owner_stats WHERE owner_key = OLD.owner_key AND open = 0 AND excepted = 0;
  DELETE FROM finding_digests WHERE fingerprint = OLD.fingerprint;
  DELETE FROM finding_packages WHERE fingerprint = OLD.fingerprint;
END;
CREATE TRIGGER findings_rollup_update AFTER UPDATE ON findings BEGIN
  UPDATE owner_stats SET
      urgent = urgent - (OLD.state = 'open' AND OLD.priority = 4),
      high = high - (OLD.state = 'open' AND OLD.priority = 3),
      medium = medium - (OLD.state = 'open' AND OLD.priority = 2),
      low = low - (OLD.state = 'open' AND OLD.priority = 1),
      open = open - (OLD.state = 'open'),
      fixable = fixable - (OLD.state = 'open' AND OLD.fix_available),
      upgradable = upgradable - (OLD.state = 'open' AND OLD.fix_class = 'upgrade'),
      exploited = exploited - (OLD.state = 'open' AND OLD.signals & 8 != 0),
      provisional = provisional - (OLD.state = 'open' AND OLD.signals & 32 != 0),
      excepted = excepted - (OLD.state = 'excepted')
    WHERE owner_key = OLD.owner_key AND OLD.state IN ('open', 'excepted');
  DELETE FROM owner_stats WHERE owner_key = OLD.owner_key AND open = 0 AND excepted = 0;
  DELETE FROM finding_digests WHERE fingerprint = OLD.fingerprint;
  DELETE FROM finding_packages WHERE fingerprint = OLD.fingerprint;
  INSERT INTO owner_stats(owner_key, namespace, owner_kind, urgent, high, medium, low, open, fixable, upgradable, exploited, provisional, excepted)
    SELECT NEW.owner_key, NEW.namespace, NEW.owner_kind,
      NEW.state = 'open' AND NEW.priority = 4,
      NEW.state = 'open' AND NEW.priority = 3,
      NEW.state = 'open' AND NEW.priority = 2,
      NEW.state = 'open' AND NEW.priority = 1,
      NEW.state = 'open',
      NEW.state = 'open' AND NEW.fix_available,
      NEW.state = 'open' AND NEW.fix_class = 'upgrade',
      NEW.state = 'open' AND NEW.signals & 8 != 0,
      NEW.state = 'open' AND NEW.signals & 32 != 0,
      NEW.state = 'excepted'
    WHERE NEW.state IN ('open', 'excepted')
    ON CONFLICT(owner_key) DO UPDATE SET
      urgent = urgent + excluded.urgent,
      high = high + excluded.high,
      medium = medium + excluded.medium,
      low = low + excluded.low,
      open = open + excluded.open,
      fixable = fixable + excluded.fixable,
      upgradable = upgradable + excluded.upgradable,
      exploited = exploited + excluded.exploited,
      provisional = provisional + excluded.provisional,
      excepted = excepted + excluded.excepted;
  INSERT INTO finding_digests(digest, fingerprint, state, priority, fix_available)
    SELECT DISTINCT d.value, NEW.fingerprint, NEW.state, NEW.priority, NEW.fix_available FROM json_each(NEW.data, '$.Digests') d WHERE d.type = 'text';
  INSERT INTO finding_packages(ecosystem, name, version, fingerprint, state, priority, fix_available)
    SELECT DISTINCT coalesce(json_extract(p.value, '$.Ecosystem'), ''), coalesce(json_extract(p.value, '$.Name'), ''),
      coalesce(json_extract(p.value, '$.Installed'), ''), NEW.fingerprint, NEW.state, NEW.priority, NEW.fix_available
    FROM json_each(NEW.data, '$.Packages') p WHERE p.type = 'object';
END;
