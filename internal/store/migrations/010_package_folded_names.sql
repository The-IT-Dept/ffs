-- The folded name of each python and java-archive package (Task 15): the name lowercased, with '_'
-- and '.' read as '-' and runs of '-' collapsed (runs of up to 32, which covers every real name).
-- That is PEP 503 normalisation. The OSV fast path finds the packages a changed PyPI or Maven record
-- names through it, because Syft keeps the case and separators of the package metadata ("Jinja2",
-- "typing_extensions") while records use the registry's form. foldName in images.go computes the
-- same value for a looked-up name; keep the two in step.
ALTER TABLE packages ADD COLUMN folded_name TEXT GENERATED ALWAYS AS (
  CASE WHEN ecosystem IN ('python', 'java-archive') THEN
    lower(replace(replace(replace(replace(replace(replace(replace(name, '_', '-'), '.', '-'),
      '--', '-'), '--', '-'), '--', '-'), '--', '-'), '--', '-'))
  END) VIRTUAL;
CREATE INDEX packages_by_folded_name ON packages (ecosystem, folded_name) WHERE folded_name IS NOT NULL;
