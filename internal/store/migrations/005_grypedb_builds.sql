-- The build time of every Grype DB the engine has loaded (Task 21), as UTC Unix nanoseconds. It is
-- the only Grype DB build history: findings.Build counts the builds after an OSV observation to
-- decide whether an OSV-only finding is still provisional. RecordGrypeDBBuild keeps the newest 30.
CREATE TABLE grypedb_builds (built INTEGER PRIMARY KEY);
