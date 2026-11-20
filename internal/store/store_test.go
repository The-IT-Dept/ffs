package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func deb(name, source string) model.Package {
	return pkg("deb", &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}, name, source)
}

func pkg(eco string, distro *model.Distro, name, source string) model.Package {
	return model.Package{Ecosystem: eco, Distro: distro, Name: name, SourceName: source, Version: "1.0", Path: "/p/" + name}
}

func put(t *testing.T, s *Store, digest string, pkgs ...model.Package) {
	t.Helper()
	require.NoError(t, s.PutSBOM(ctx, digest, nil, pkgs))
}

func names(pkgs []model.Package) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.Name
	}
	return out
}

func mt(digest, pkgID, advisory string, source model.MatchSource) model.Match {
	return model.Match{ImageDigest: digest, PackageID: pkgID, AdvisoryID: advisory, Source: source, FixState: model.FixFixed}
}

// seed stores ms with one ReplaceMatches call per (source, digest).
func seed(t *testing.T, s *Store, ms ...model.Match) {
	t.Helper()
	type group struct {
		source model.MatchSource
		digest string
	}
	groups := map[group][]model.Match{}
	var order []group
	for _, m := range ms {
		g := group{m.Source, m.ImageDigest}
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], m)
	}
	for _, g := range order {
		_, err := s.ReplaceMatches(ctx, MatchScope{Source: g.source, Digests: []string{g.digest}}, groups[g])
		require.NoError(t, err)
	}
}

// keys returns "<source>:<advisoryID>" for each stored match of digest.
func keys(t *testing.T, s *Store, digest string) []string {
	t.Helper()
	ms, err := s.MatchesForDigests(ctx, []string{digest})
	require.NoError(t, err)
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = string(m.Source) + ":" + m.AdvisoryID
	}
	return out
}

func fd(fp string, state model.FindingState, priority model.Priority) model.Finding {
	return model.Finding{
		Fingerprint: fp,
		Owner:       model.OwnerRef{Kind: "Deployment", Namespace: "netbox", Name: "netbox"},
		ImageRepo:   "ghcr.io/x",
		AdvisoryID:  "CVE-2026-0001",
		State:       state,
		Priority:    priority,
		LastSeen:    t0,
	}
}

func tr(fp string, from, to model.FindingState) model.Transition {
	return model.Transition{Fingerprint: fp, FromState: from, ToState: to, Trigger: model.TriggerNewAdvisory, At: t0}
}

func fps(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Fingerprint
	}
	return out
}

func TestOpen_WALAndIdempotentMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ffs.db")
	s, err := Open(ctx, path)
	require.NoError(t, err)
	var mode string
	require.NoError(t, s.rdb.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode))
	require.Equal(t, "wal", mode)
	var appliedAt int64
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT applied_at FROM schema_migrations WHERE name = '001_init.sql'`).Scan(&appliedAt))
	require.NoError(t, s.Close())

	s, err = Open(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	var n int
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE name = '001_init.sql'`).Scan(&n))
	require.Equal(t, 1, n)
	var again int64
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT applied_at FROM schema_migrations WHERE name = '001_init.sql'`).Scan(&again))
	require.Equal(t, appliedAt, again) // not re-applied
}

// planOf returns the detail column of EXPLAIN QUERY PLAN for q on the read pool.
func planOf(t *testing.T, s *Store, q string, args ...any) []string {
	t.Helper()
	rows, err := s.rdb.QueryContext(ctx, `EXPLAIN QUERY PLAN `+q, args...)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &unused, &detail))
		plan = append(plan, detail)
	}
	require.NoError(t, rows.Err())
	return plan
}
