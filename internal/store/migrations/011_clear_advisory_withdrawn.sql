-- Advisory.Withdrawn used to be ORed in from any withdrawn OSV record that aliased the advisory,
-- including GitHub's withdrawn duplicate GHSAs that keep a live CVE as an alias, and it never
-- cleared, so findings.Build dropped every match on those live CVEs. Only a REJECTED cvelistV5
-- record sets it now. The stored flags cannot tell the two causes apart, so all are cleared; a
-- rejected CVE's matches go through each matcher's own source (OSV withdrawal, cvelist ranges,
-- the next Grype DB).
UPDATE advisories SET data = json_set(data, '$.Withdrawn', json('false'))
  WHERE json_extract(data, '$.Withdrawn') = 1;
