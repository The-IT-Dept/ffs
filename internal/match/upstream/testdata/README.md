# Test data

- `CVE-2024-11236.json` is the OSV.dev `GIT` record for a php-src advisory, trimmed (the
  `related` list and most references removed). It has no `versions` list, only
  `database_specific.extracted_events` on its GIT range (8.3.0 to 8.3.14, among others).
- `CVE-2024-27983.json` is a constructed node `GIT` record in the OSV.dev layout. Its `versions`
  list holds release tags including `v20.11.1`, and its extracted ranges follow the Node.js
  advisory (fixed in 18.20.1, 20.12.1 and 21.7.2). The commit id in its events is not real.
- `cna-php.json` is a constructed cvelistV5 affected entry for the `PHP Group`/`PHP` product,
  with the `8.3.*` range ending at `lessThan` 8.3.15. Tests store it under a fixture advisory id.
