-- The Exception that excepts each excepted finding, as an indexed generated column (fix wave F36).
-- The Exception reconciler counts the findings an Exception excepts on every reconcile; reading the
-- column through its partial index replaces decoding every open and excepted finding's JSON.
ALTER TABLE findings ADD COLUMN excepted_by TEXT GENERATED ALWAYS AS (
  CASE WHEN state = 'excepted' THEN json_extract(data, '$.ExceptedBy') END) VIRTUAL;
CREATE INDEX findings_by_excepted_by ON findings (excepted_by) WHERE excepted_by IS NOT NULL;
