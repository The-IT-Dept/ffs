-- The names grype searched for each catalogued digest (Task 13): kind 'pkg' holds package and
-- upstream package names, kind 'cpe' the CPE products of packages matched by CPE. All lowercased.
-- A Grype DB diff's changed keys select the digests to re-match through grype_keys_by_name.
CREATE TABLE grype_keys (digest TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('pkg','cpe')), name TEXT NOT NULL,
                         PRIMARY KEY (digest, kind, name)) WITHOUT ROWID;
CREATE INDEX grype_keys_by_name ON grype_keys (kind, name);
