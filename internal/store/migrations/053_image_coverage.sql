-- Image kind and coverage class for the web UI's image explorer and coverage view, generated from
-- each image row; CoverageClassOf in readmodel.go is the Go copy of the cov_class rule.
ALTER TABLE images ADD COLUMN image_kind TEXT GENERATED ALWAYS AS (CASE WHEN digest LIKE 'k8s:%' OR digest LIKE 'runtime:%' THEN 'synthetic'
  WHEN digest LIKE 'nodegroup:%' THEN 'host' ELSE 'container' END) VIRTUAL;
ALTER TABLE images ADD COLUMN cov_unattributed INTEGER GENERATED ALWAYS AS (coalesce(json_extract(coverage, '$.UnattributedELF'), 0)) VIRTUAL;
ALTER TABLE images ADD COLUMN cov_rust INTEGER GENERATED ALWAYS AS (coalesce(json_extract(coverage, '$.RustWithoutAuditable'), 0)) VIRTUAL;
ALTER TABLE images ADD COLUMN cov_class TEXT GENERATED ALWAYS AS (CASE WHEN status != 'catalogued' THEN 'none'
  WHEN source = 'attestation' OR cov_unattributed > 0 OR cov_rust > 0 THEN 'partial' ELSE 'full' END) VIRTUAL;
CREATE INDEX images_kind_cov ON images(image_kind, status, cov_class, source);
CREATE INDEX image_tags_digest ON image_tags(digest);
