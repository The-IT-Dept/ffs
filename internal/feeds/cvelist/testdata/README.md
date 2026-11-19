# Test data

CVE records from the CVE Program's cvelistV5 repository
(https://github.com/CVEProject/cvelistV5), used under the CVE Program Terms of Use. They are
trimmed: credits, timelines, problem types, generator fields and most references are removed,
and the Linux kernel record keeps only a few of its affected versions.

| File | Why |
|---|---|
| `CVE-2024-11236.json` | php CNA, `8.3.*` ranges and CVSS 3.1 critical 9.8 |
| `CVE-2024-22019.json` | node CNA (`NodeJS`/`Node`), `N.*` upper bounds and CVSS 3.0 |
| `CVE-2024-12254.json` | PSF CNA with CVSS 4.0, and CISA-ADP CVSS 3.1 |
| `CVE-2024-46981.json` | GitHub CNA with GitHub-style ranges (`>= 7.4.0, < 7.4.2`) |
| `CVE-2024-53104.json` | no CNA metrics; CISA-ADP CVSS 3.1 only |
| `CVE-2025-59909.json` | a `REJECTED` record |
