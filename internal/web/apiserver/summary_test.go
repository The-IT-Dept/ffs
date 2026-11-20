package apiserver_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func TestSummary_ClusterHeadline(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.Summary](t, get(t, h, "/api/v1/summary"))
	require.Equal(t, apigen.ScopeRef{Scope: "cluster", Kind: apigen.ScopeKindCluster, Label: "test"}, got.Scope)
	require.Equal(t, 2, got.Reachable, "web and node-exporter")
	require.Equal(t, 2, got.ReachableUrgent)
	require.Equal(t, smallOpen, got.Findings)
	require.Equal(t, smallOpenTotal, got.Open)
	require.Equal(t, 9, got.Fixable)
	require.Equal(t, 2, got.Exploited)
	require.Equal(t, apigen.CoverageFigure{InUse: 10, SeenInto: 6, Full: 4}, got.Coverage)
	require.False(t, got.Feeds.Fresh)
	require.Equal(t, []string{"kev"}, got.Feeds.Stale)
	cov := ok[apigen.Coverage](t, get(t, h, "/api/v1/coverage"))
	require.Equal(t, cov.TotalGaps, got.Gaps)
	require.Positive(t, got.Gaps)

	ns := ok[apigen.Summary](t, get(t, h, "/api/v1/summary?scope=namespace:payments"))
	require.Zero(t, ns.Reachable, "an internal-only entry point exposes nothing")
	require.Zero(t, ns.ReachableUrgent)
	require.Equal(t, apigen.PriorityCounts{High: 1}, ns.Findings)

	node := ok[apigen.Summary](t, get(t, h, "/api/v1/summary?scope=node:worker-1"))
	require.Equal(t, 1, node.Reachable)
	require.Equal(t, apigen.PriorityCounts{High: 1}, node.Findings)
	require.Equal(t, apigen.CoverageFigure{InUse: 1, SeenInto: 1, Full: 1}, node.Coverage)
}

func TestSummary_FreshInstallReportsCoverageNotClean(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, t.TempDir()+"/ffs.db")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	require.NoError(t, st.UpsertOwner(ctx, model.Owner{Ref: webtest.Web, UpdatedAt: webtest.Now, Containers: []model.ContainerUse{{
		Name: "app", Kind: model.ContainerRegular, ImageRef: "docker.io/library/nginx:1.30.6", Repo: "docker.io/library/nginx",
		Digest: webtest.DigestWeb, Platform: "linux/amd64"}}}))
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: webtest.DigestWeb, Repo: "docker.io/library/nginx",
		Status: model.ImagePending}))
	cfg := config.Default()
	cfg.ClusterName = webtest.ClusterName
	h := apiserver.New(apiserver.Options{Store: st, Config: cfg, Feeds: []apiserver.FeedInfo{{Name: "osv", StaleAfter: 2 * time.Hour}},
		Now: func() time.Time { return webtest.Now }}).Handler()

	got := ok[apigen.Summary](t, get(t, h, "/api/v1/summary"))
	require.Equal(t, apigen.PriorityCounts{}, got.Findings)
	require.Zero(t, got.Open)
	require.Equal(t, apigen.CoverageFigure{InUse: 1}, got.Coverage, "nothing seen into is not the same as nothing found")
	require.False(t, got.Feeds.Fresh)
	require.Equal(t, []string{"osv"}, got.Feeds.Stale)
	require.Equal(t, 2, got.Gaps)

	cov := ok[apigen.Coverage](t, get(t, h, "/api/v1/coverage"))
	var codes []apigen.GapCode
	for _, g := range cov.Gaps {
		codes = append(codes, g.Code)
	}
	require.Equal(t, []apigen.GapCode{apigen.GapCodeFeedStale, apigen.GapCodePending}, codes)
	require.Nil(t, cov.Funnel.Pods, "no pod counts without the inventory")
}
