package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// queryPlan returns the EXPLAIN QUERY PLAN details of query, bound to args, one per line.
func queryPlan(t *testing.T, s *Store, query string, args ...any) string {
	t.Helper()
	rows, err := s.rdb.QueryContext(ctx, `EXPLAIN QUERY PLAN `+query, args...)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &notused, &detail))
		lines = append(lines, detail)
	}
	require.NoError(t, rows.Err())
	return strings.Join(lines, "\n")
}

func TestStore_ClassifiedPackages(t *testing.T) {
	s := newStore(t)
	for _, img := range []model.Image{
		{Digest: "sha256:cat", Repo: "ghcr.io/x", Status: model.ImageCatalogued, CataloguedAt: t0},
		{Digest: "sha256:pending", Repo: "ghcr.io/y", Status: model.ImagePending},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	require.NoError(t, s.PutSBOM(ctx, "sha256:cat", nil, []model.Package{
		{Ecosystem: "deb", Name: "openssl", Version: "3.0.15"},
		{Ecosystem: "binary", Name: "traefik", Version: "3.2.0", Classifier: "traefik-binary", Path: "/usr/local/bin/traefik"},
	}))
	byDigest, err := s.ClassifiedPackages(ctx, []string{"sha256:cat", "sha256:pending"})
	require.NoError(t, err)
	require.Len(t, byDigest, 1)
	require.Len(t, byDigest["sha256:cat"], 1)
	require.Equal(t, "traefik", byDigest["sha256:cat"][0].Name)
	require.Equal(t, "traefik-binary", byDigest["sha256:cat"][0].Classifier)
}
