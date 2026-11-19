-- The index names of each cached OSV record (Task 14): the normalised package names (or, in the GIT
-- bucket, the normalised repository URLs) a record can match, so a newly catalogued image finds its
-- cached records by name. Rows follow osv_records: replaced when a record changes, removed with it.
CREATE TABLE osv_record_names (bucket TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (bucket, id, name)) WITHOUT ROWID;
CREATE INDEX osv_record_names_by_name ON osv_record_names (bucket, name);
-- OSVRecordsByID looks records up by id across buckets; the primary key leads with the bucket.
CREATE INDEX osv_records_by_id ON osv_records (id);
