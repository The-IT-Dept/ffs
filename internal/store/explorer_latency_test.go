package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// The read paths migration 055 and the single-evaluation pages serve (the API latency gate).

func TestPackagesPage_EpochFormsCountEachImageOnce(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	beside := model.Package{Ecosystem: "rpm", Name: "bash", Epoch: "1", Version: "5.2-1", Path: "/var/lib/rpm"}
	inside := model.Package{Ecosystem: "rpm", Name: "bash", Epoch: "1", Version: "1:5.2-1", Path: "/var/lib/rpm"}
	require.Equal(t, beside.Installed(), inside.Installed())
	put(t, s, "sha256:web", beside)
	put(t, s, "sha256:worker", inside)
	put(t, s, "sha256:api", beside, inside)

	for _, sc := range []model.Scope{{Kind: model.ScopeCluster}, {Kind: model.ScopeNamespace, Value: "shop"}} {
		page, err := s.PackagesPage(ctx, PackageEntityQuery{Scope: sc})
		require.NoError(t, err)
		var bash []PackageRow
		for _, r := range page.Rows {
			if r.Name == "bash" {
				bash = append(bash, r)
			}
		}
		require.Len(t, bash, 1, "one row per installed version: %v", sc)
		require.Equal(t, "1:5.2-1", bash[0].Version)
		want := map[model.ScopeKind]int{model.ScopeCluster: 3, model.ScopeNamespace: 2}[sc.Kind]
		require.Equal(t, want, bash[0].Images, "an image holding both forms counts once: %v", sc)
		require.Equal(t, want, bash[0].Workloads, "%v", sc)
	}
}

func TestExplorerPages_TotalWhenTheCursorIsPastTheLastRow(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	put(t, s, "sha256:web", model.Package{Ecosystem: "deb", Name: "libc6", Version: "2.36-9"})
	put(t, s, "sha256:worker", model.Package{Ecosystem: "deb", Name: "tzdata", Version: "2025a"})

	all, err := s.PackagesPage(ctx, PackageEntityQuery{Sort: "name"})
	require.NoError(t, err)
	require.Equal(t, 2, all.Total)
	past, err := s.PackagesPage(ctx, PackageEntityQuery{Sort: "name", After: encodeCursor("packages:name", []any{"zzz", "zzz", "zzz"})})
	require.NoError(t, err)
	require.Empty(t, past.Rows)
	require.Equal(t, all.Total, past.Total)

	imgs, err := s.ImagesPage(ctx, ImageQuery{Sort: ImageRepoSort})
	require.NoError(t, err)
	require.Positive(t, imgs.Total)
	pastImgs, err := s.ImagesPage(ctx, ImageQuery{Sort: ImageRepoSort, After: encodeCursor("images:repo", []any{"zzz", "zzz"})})
	require.NoError(t, err)
	require.Empty(t, pastImgs.Rows)
	require.Equal(t, imgs.Total, pastImgs.Total)

	groups, err := s.FindingGroups(ctx, FindingQuery{}, GroupAdvisory)
	require.NoError(t, err)
	require.Positive(t, groups.Groups)
	pastGroups, err := s.FindingGroups(ctx, FindingQuery{After: encodeCursor("group:advisory",
		[]any{int64(0), int64(0), int64(0), int64(0), "zzz"})}, GroupAdvisory)
	require.NoError(t, err)
	require.Empty(t, pastGroups.Rows)
	require.Equal(t, groups.Groups, pastGroups.Groups)
	require.Equal(t, groups.Findings, pastGroups.Findings)
}

func TestFindingsPage_RanksUnnarrowedPagesOnTheGroupsIndex(t *testing.T) {
	s := newStore(t)
	seedFindingsExplorer(t, s)
	for _, sort := range []FindingSort{SortPriority, SortSeverity, SortPublished, SortEPSS, SortAdvisory, SortWorkload, SortNamespace} {
		for _, q := range []FindingQuery{{Sort: sort}, {Sort: sort, Scope: model.Scope{Kind: model.ScopeNamespace, Value: "shop"},
			Priorities: []model.Priority{model.PriorityUrgent}, Signals: []model.Signal{model.SignalExposed}, Q: "web"}} {
			ps, err := findingPageStmt(q)
			require.NoError(t, err)
			require.Contains(t, queryPlan(t, s, ps.query, ps.args...), "findings_groups", sort)
		}
	}
	for name, q := range map[string]FindingQuery{
		"workload": {Scope: model.Scope{Kind: model.ScopeWorkload, Value: "Deployment/shop/web"}},
		"image":    {Scope: model.Scope{Kind: model.ScopeImage, Value: "sha256:web"}},
		"advisory": {Advisory: "CVE-2026-0001"}, "package": {Package: "openssl"},
		"resolved": {States: []model.FindingState{model.StateResolved}},
	} {
		require.False(t, groupsIndexed(q), name)
		ps, err := findingPageStmt(q)
		require.NoError(t, err)
		require.NotContains(t, ps.query, "findings_groups", name)
	}
}

func TestOwnerEntities_PrivilegeFindsEachContainersImageByDigest(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	plan := queryPlan(t, s, `SELECT privileged FROM owner_entities`)
	containers, images := strings.Index(plan, "SCAN c VIRTUAL TABLE"), strings.Index(plan, "SEARCH i USING")
	require.GreaterOrEqual(t, containers, 0, plan)
	require.Greater(t, images, containers, "the containers drive the image lookup: %s", plan)
	require.Contains(t, plan[images:], "(digest=?)", plan)

	ents, err := s.OwnerEntities(ctx, model.Scope{Kind: model.ScopeCluster})
	require.NoError(t, err)
	privileged := map[string]bool{}
	for _, e := range ents {
		privileged[e.Key] = e.Privileged
	}
	require.True(t, privileged[exAPI.Key()], "a container running as the root image user of a catalogued image")
	require.False(t, privileged[exWeb.Key()])
}
