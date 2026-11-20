-- Open-finding rollups for the API and dashboard (fix wave F37). Counting open findings by owner and
-- by advisory decoded every open finding's JSON on each request. This index holds every column and
-- expression the rollups read (store/rollups.go uses the same json_extract expressions), so they
-- scan the index alone and read no finding row.
CREATE INDEX findings_rollup ON findings(state, advisory_id, owner_key, priority,
  json_extract(data, '$.Severity'), json_extract(data, '$.FixAvailable'));
