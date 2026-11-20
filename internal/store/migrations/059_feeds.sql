-- The rows of each OSV bucket's modified_id.csv the osv feed has taken in within its poll overlap,
-- the hour below the watermark: a later poll reads that hour again for records listed late, with a
-- modified time older than rows already read, and takes only the rows not recorded here.
CREATE TABLE osv_listed (bucket TEXT NOT NULL, id TEXT NOT NULL, modified INTEGER NOT NULL, PRIMARY KEY (bucket, id)) WITHOUT ROWID;
