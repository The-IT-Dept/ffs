package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
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

// LiveDigests returns the sorted digests some owner runs or some upgrade suggestion holds as a
// candidate: the images whose matches findings and suggestions are built from.
func (s *Store) LiveDigests(ctx context.Context) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `SELECT digest FROM owner_images UNION SELECT digest FROM candidates ORDER BY digest`)
}

// CataloguedLiveSBOMs counts the live digests (LiveDigests) with a catalogued SBOM, other than the
// synthetic Kubernetes and runtime ones: the images and node groups a full Grype DB re-match reads.
func (s *Store) CataloguedLiveSBOMs(ctx context.Context) (int, error) {
	var n int
	err := s.rdb.QueryRowContext(ctx, `
		WITH live(digest) AS (SELECT digest FROM owner_images UNION SELECT digest FROM candidates)
		SELECT COUNT(*) FROM live l JOIN images i ON i.digest = l.digest
		WHERE i.status = ? AND l.digest NOT LIKE 'k8s:%' AND l.digest NOT LIKE 'runtime:%'`,
		string(model.ImageCatalogued)).Scan(&n)
	return n, err
}

// DigestsAwaitingGrype returns the sorted live (LiveDigests), catalogued, non-synthetic digests a
// Grype DB built at built must re-match even though its diff did not touch their packages:
//   - those with no grype search keys, catalogued while no DB was loaded;
//   - those holding an OSV match that grype has not ruled on: observed before built, with no grype
//     match on the same package and advisory from a DB built after the observation, and still
//     provisional (fewer than two recorded builds after the observation). Grype forms its
//     not-affected opinions from OSV hints only when it matches the image (spec §6.5).
func (s *Store) DigestsAwaitingGrype(ctx context.Context, built time.Time) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `
		WITH live(digest) AS (SELECT digest FROM owner_images UNION SELECT digest FROM candidates)
		SELECT l.digest FROM live l JOIN images i ON i.digest = l.digest
		WHERE i.status = ? AND l.digest NOT LIKE 'k8s:%' AND l.digest NOT LIKE 'runtime:%'
		AND (NOT EXISTS (SELECT 1 FROM grype_keys k WHERE k.digest = l.digest)
			OR EXISTS (SELECT 1 FROM matches o WHERE o.digest = l.digest AND o.source = ? AND o.observed_at < ?
				AND (SELECT COUNT(*) FROM grypedb_builds b WHERE b.built > o.observed_at) < 2
				AND NOT EXISTS (SELECT 1 FROM matches g WHERE g.digest = o.digest AND g.package_id = o.package_id
					AND g.advisory_id = o.advisory_id AND g.source = ? AND g.db_built > o.observed_at)))
		ORDER BY l.digest`,
		string(model.ImageCatalogued), string(model.SourceOSV), built.UTC().UnixNano(), string(model.SourceGrype))
}
