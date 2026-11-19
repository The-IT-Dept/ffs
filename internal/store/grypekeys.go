package store

import (
	"context"
	"database/sql"
	"strings"
)

const (
	grypeKeyPkg = "pkg"
	grypeKeyCPE = "cpe"
)

// PutGrypeKeys replaces the grype search keys of digest: the package names grype searched by
// (pkgNames) and the CPE products it searched by (cpeProducts). Names are stored lowercased.
func (s *Store) PutGrypeKeys(ctx context.Context, digest string, pkgNames, cpeProducts []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM grype_keys WHERE digest = ?`, digest); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO grype_keys(digest, kind, name) VALUES(?, ?, ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = ins.Close() }()
		for _, k := range []struct {
			kind  string
			names []string
		}{{grypeKeyPkg, pkgNames}, {grypeKeyCPE, cpeProducts}} {
			for _, n := range k.names {
				if n == "" {
					continue
				}
				if _, err := ins.ExecContext(ctx, digest, k.kind, strings.ToLower(n)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// DigestsForGrypeKeys returns the sorted digests whose grype keys include any of pkgNames (as a
// package name) or cpeProducts (as a CPE product), compared case-insensitively.
func (s *Store) DigestsForGrypeKeys(ctx context.Context, pkgNames, cpeProducts []string) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `
		SELECT digest FROM grype_keys WHERE kind = ? AND name IN (SELECT value FROM json_each(?))
		UNION
		SELECT digest FROM grype_keys WHERE kind = ? AND name IN (SELECT value FROM json_each(?))
		ORDER BY digest`, grypeKeyPkg, idList(lowered(pkgNames)), grypeKeyCPE, idList(lowered(cpeProducts)))
}

// GrypeDigests returns the sorted digests that have grype keys.
func (s *Store) GrypeDigests(ctx context.Context) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `SELECT DISTINCT digest FROM grype_keys ORDER BY digest`)
}

func lowered(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.ToLower(n)
	}
	return out
}
