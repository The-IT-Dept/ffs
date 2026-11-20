-- When ffs first stored each cached OSV record's current affected content (F2), as UTC Unix
-- nanoseconds. Spec §6.5 gives grype an opinion only through a DB built after ffs observed the OSV
-- record, so the fast path stamps its matches with this time instead of the time a match row was
-- first written (which made every newly catalogued digest OSV-ruled). PutOSVRecord sets it on
-- insert and whenever the affected hash changes. Rows cached before this migration take the
-- earliest stored OSV match on their advisory, or the migration time.
ALTER TABLE osv_records ADD COLUMN observed INTEGER;
UPDATE osv_records SET observed = COALESCE(
  (SELECT MIN(m.observed_at) FROM matches m WHERE m.source = 'osv' AND m.advisory_id =
    COALESCE((SELECT a.canonical FROM advisory_aliases a WHERE a.alias = osv_records.id), osv_records.id)),
  CAST(strftime('%s', 'now') AS INTEGER) * 1000000000);
