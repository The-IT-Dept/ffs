# Test data

`vunnel/debian/results/debian-12/cve-2022-38178.json` and `cve-2025-13012.json` are copied
unchanged from Grype v0.122.1,
`grype/db/v6/diff/testdata/inputs/debian/results/debian-12/`
(https://github.com/anchore/grype). Copyright (c) Anchore, Inc., licensed under the Apache
License, Version 2.0.

`grypedbtest.BuildDB` copies the `vunnel` tree to a temporary directory and builds a Grype v6
database from it.
