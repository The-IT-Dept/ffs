-- Facts about the store kept across controller restarts, by key. controller_version is the version
-- of the controller that last started on this store: a new version lifts the quarantines a crash of
-- the previous one caused (Store.ResetCrashQuarantines).
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
