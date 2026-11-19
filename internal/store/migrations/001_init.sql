-- Core tables. Times are INTEGER UTC Unix nanoseconds, NULL when unset.
-- Nested model values are JSON text columns.
CREATE TABLE images(digest TEXT PRIMARY KEY, index_digest TEXT NOT NULL DEFAULT '', repo TEXT NOT NULL, platform TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL, status_reason TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', version_annotation TEXT NOT NULL DEFAULT '',
  config_user TEXT NOT NULL DEFAULT '',
  coverage TEXT NOT NULL DEFAULT '{}', catalogued_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0, quarantined_until INTEGER);
CREATE INDEX images_status ON images(status);
CREATE INDEX images_repo ON images(repo);
CREATE TABLE image_tags(repo TEXT NOT NULL, tag TEXT NOT NULL, digest TEXT NOT NULL, resolved_at INTEGER NOT NULL, PRIMARY KEY(repo, tag));
CREATE TABLE sboms(digest TEXT PRIMARY KEY, syft_zst BLOB NOT NULL, raw_size INTEGER NOT NULL);
CREATE TABLE packages(id TEXT PRIMARY KEY, digest TEXT NOT NULL, ecosystem TEXT NOT NULL,
  distro_id TEXT NOT NULL DEFAULT '', distro_version TEXT NOT NULL DEFAULT '', distro_codename TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL, version TEXT NOT NULL, epoch TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL DEFAULT '',
  source_name TEXT NOT NULL DEFAULT '', source_version TEXT NOT NULL DEFAULT '', purl TEXT NOT NULL DEFAULT '',
  cpes TEXT NOT NULL DEFAULT '[]', path TEXT NOT NULL DEFAULT '', layer TEXT NOT NULL DEFAULT '',
  classifier TEXT NOT NULL DEFAULT '', go_stdlib INTEGER NOT NULL DEFAULT 0, syft_id TEXT NOT NULL DEFAULT '');
CREATE INDEX packages_digest ON packages(digest);
CREATE INDEX packages_by_name ON packages(ecosystem, distro_id, distro_version, name);
CREATE INDEX packages_by_source ON packages(ecosystem, distro_id, distro_version, source_name);
CREATE TABLE owners(key TEXT PRIMARY KEY, namespace TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER);
CREATE TABLE owner_images(owner_key TEXT NOT NULL, digest TEXT NOT NULL, container TEXT NOT NULL, PRIMARY KEY(owner_key, digest, container));
CREATE INDEX owner_images_digest ON owner_images(digest);
CREATE TABLE advisories(id TEXT PRIMARY KEY, data TEXT NOT NULL, observed INTEGER NOT NULL);
CREATE TABLE advisory_aliases(alias TEXT PRIMARY KEY, canonical TEXT NOT NULL);   -- canonical maps to itself too
CREATE INDEX advisory_aliases_canonical ON advisory_aliases(canonical);
CREATE TABLE matches(digest TEXT NOT NULL, package_id TEXT NOT NULL, advisory_id TEXT NOT NULL, source TEXT NOT NULL,
  fix_state TEXT NOT NULL, fixed_versions TEXT NOT NULL DEFAULT '[]', vendor_severity INTEGER NOT NULL DEFAULT 0,
  vendor_severity_source TEXT NOT NULL DEFAULT '', namespace TEXT NOT NULL DEFAULT '', db_built INTEGER, observed_at INTEGER NOT NULL,
  PRIMARY KEY(digest, package_id, advisory_id, source));
CREATE INDEX matches_advisory ON matches(advisory_id);
CREATE INDEX matches_package ON matches(package_id);
CREATE TABLE findings(fingerprint TEXT PRIMARY KEY CHECK(fingerprint <> ''), owner_key TEXT NOT NULL, namespace TEXT NOT NULL,
  advisory_id TEXT NOT NULL, state TEXT NOT NULL, priority INTEGER NOT NULL, data TEXT NOT NULL, resolved_at INTEGER);
CREATE INDEX findings_owner ON findings(owner_key);
CREATE INDEX findings_advisory ON findings(advisory_id);
CREATE INDEX findings_state_priority ON findings(state, priority);
CREATE TABLE transitions(id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL CHECK(fingerprint <> ''), data TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX transitions_fingerprint ON transitions(fingerprint);
CREATE TABLE cursors(consumer TEXT PRIMARY KEY, id INTEGER NOT NULL);
CREATE TABLE feeds(name TEXT PRIMARY KEY, watermark TEXT NOT NULL DEFAULT '', last_success INTEGER, last_attempt INTEGER,
  last_error TEXT NOT NULL DEFAULT '', meta TEXT NOT NULL DEFAULT '{}');
CREATE TABLE osv_records(ecosystem TEXT NOT NULL, id TEXT NOT NULL, modified INTEGER NOT NULL, affected_hash TEXT NOT NULL,
  raw_zst BLOB NOT NULL, PRIMARY KEY(ecosystem, id));
CREATE INDEX osv_records_modified ON osv_records(ecosystem, modified);
CREATE TABLE upstream_ranges(advisory_id TEXT NOT NULL, product_key TEXT NOT NULL, ranges BLOB NOT NULL, PRIMARY KEY(advisory_id, product_key));
CREATE INDEX upstream_ranges_product ON upstream_ranges(product_key);
