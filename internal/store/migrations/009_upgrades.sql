-- Upgrade suggestions (Task 31). suggestions holds one model.Suggestion (JSON) per owner and image
-- repository; it is the only source of Finding.Suggestion. candidates holds the platform manifests
-- each suggestion scored, so a match change on one invalidates the suggestion and image pruning
-- keeps them. announcements holds the target last announced with UpgradeAvailable transitions per
-- owner and repository; it outlives a suggestion withdrawn by a candidate's match change, so
-- resolving to the same target again does not announce it twice.
CREATE TABLE suggestions (owner_key TEXT NOT NULL, repo TEXT NOT NULL, from_tag TEXT NOT NULL, data TEXT NOT NULL,
  computed_at INTEGER NOT NULL, PRIMARY KEY (owner_key, repo));
CREATE TABLE candidates (owner_key TEXT NOT NULL, repo TEXT NOT NULL, tag TEXT NOT NULL, tier TEXT NOT NULL,
  platform TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY (owner_key, repo, tag, platform));
CREATE INDEX candidates_digest ON candidates (digest);
CREATE TABLE announcements (owner_key TEXT NOT NULL, repo TEXT NOT NULL, to_tag TEXT NOT NULL, to_digest TEXT NOT NULL,
  PRIMARY KEY (owner_key, repo));
