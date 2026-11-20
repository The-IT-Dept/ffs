-- Acquisition bookkeeping that must survive a restart.
-- images_unmatched lists the images whose SBOM is stored but whose first full match has not
-- completed; attempts counts the match runs started, so an image that keeps stopping the matcher is
-- given up on rather than retried in a loop. acquisitions_inflight lists the SBOM acquisitions in
-- progress: a row left from a previous process means that process stopped during the attempt, which
-- counts against the image like a crash of the cataloguer.
CREATE TABLE images_unmatched (digest TEXT PRIMARY KEY, since INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE acquisitions_inflight (digest TEXT PRIMARY KEY, started INTEGER NOT NULL);
