package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// queryPlan returns the EXPLAIN QUERY PLAN details of query, one per line.
func queryPlan(t *testing.T, s *Store, query string) string {
	t.Helper()
	rows, err := s.rdb.QueryContext(ctx, `EXPLAIN QUERY PLAN `+query)
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

func TestStore_OpenRollups(t *testing.T) {
	s := newStore(t)
	mk := func(fp, owner, adv string, sev model.Severity, p model.Priority, state model.FindingState, fix bool) model.Finding {
		f := fd(fp, state, p)
		f.Owner = model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: owner}
		f.AdvisoryID, f.Severity, f.FixAvailable = adv, sev, fix
		return f
	}
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{
		mk("a-web", "web", "CVE-A", model.SeverityHigh, model.PriorityHigh, model.StateOpen, false),
		mk("a-api", "api", "CVE-A", model.SeverityCritical, model.PriorityUrgent, model.StateOpen, true),
		mk("b-web", "web", "CVE-B", model.SeverityLow, model.PriorityLow, model.StateOpen, false),
		mk("c-web", "web", "CVE-C", model.SeverityMedium, model.PriorityMedium, model.StateExcepted, true),
		mk("d-api", "api", "CVE-D", model.SeverityHigh, model.PriorityHigh, model.StateResolved, true),
	}, nil))

	rs, err := s.OpenAdvisoryRollups(ctx)
	require.NoError(t, err)
	require.Equal(t, []AdvisoryRollup{
		{AdvisoryID: "CVE-A", HighestPriority: model.PriorityUrgent, Severity: model.SeverityCritical, Owners: 2, Findings: 2, FixAvailable: true},
		{AdvisoryID: "CVE-B", HighestPriority: model.PriorityLow, Severity: model.SeverityLow, Owners: 1, Findings: 1},
	}, rs)

	counts, err := s.OpenCountsByOwner(ctx)
	require.NoError(t, err)
	require.Equal(t, map[string]map[model.Priority]int{
		"Deployment/shop/web": {model.PriorityHigh: 1, model.PriorityLow: 1},
		"Deployment/shop/api": {model.PriorityUrgent: 1},
	}, counts)

	// both rollups read only the index: no finding's JSON is decoded or even read
	for _, q := range []string{advisoryRollupQuery, ownerCountsQuery} {
		require.Contains(t, queryPlan(t, s, q), "USING COVERING INDEX findings_rollup", q)
	}
}

func TestStore_ImageRollups(t *testing.T) {
	s := newStore(t)
	for _, img := range []model.Image{
		{Digest: "sha256:cat", Repo: "ghcr.io/x", Status: model.ImageCatalogued, CataloguedAt: t0},
		{Digest: "sha256:pending", Repo: "ghcr.io/y", Status: model.ImagePending},
		{Digest: "unknown:ghcr.io/z:1", Repo: "ghcr.io/z", Status: model.ImageUnresolvable},
		{Digest: "k8s:1.35.1", Repo: "kubernetes", Status: model.ImageCatalogued, CataloguedAt: t0},
		{Digest: "sha256:unused", Repo: "ghcr.io/u", Status: model.ImagePending},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"},
		Containers: []model.ContainerUse{{Name: "a", Digest: "sha256:cat"}, {Name: "b", Digest: "sha256:pending"},
			{Name: "c", Digest: "unknown:ghcr.io/z:1"}, {Name: "d", Digest: "sha256:norow"}}}))
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Cluster", Name: "test"},
		Containers: []model.ContainerUse{{Name: "kubernetes", Digest: "k8s:1.35.1"}}}))

	cat, uncat, err := s.InUseImageCoverage(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, cat, "the synthetic k8s digest is not a container image")
	require.Equal(t, 3, uncat, "pending, unresolvable and a digest with no row yet")

	st, err := s.ImageStatuses(ctx, []string{"sha256:cat", "unknown:ghcr.io/z:1", "sha256:norow"})
	require.NoError(t, err)
	require.Equal(t, map[string]model.ImageStatus{"sha256:cat": model.ImageCatalogued, "unknown:ghcr.io/z:1": model.ImageUnresolvable}, st)

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
