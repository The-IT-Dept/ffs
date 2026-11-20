package apiserver_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func gapsByCode(t *testing.T, gaps []apigen.Gap, code apigen.GapCode) []apigen.Gap {
	t.Helper()
	var out []apigen.Gap
	for _, g := range gaps {
		if g.Code == code {
			out = append(out, g)
		}
	}
	require.NotEmpty(t, out, "no %s gap", code)
	return out
}

func TestCoverage_FunnelAndGaps(t *testing.T) {
	f := webtest.Open(t)
	kev, err := f.Store.FeedState(t.Context(), "kev")
	require.NoError(t, err)
	kev.LastError = "fetch catalogue: 503 Service Unavailable"
	require.NoError(t, f.Store.PutFeedState(t.Context(), kev))
	h := handlerOf(f)

	got := ok[apigen.Coverage](t, get(t, h, "/api/v1/coverage"))
	require.Equal(t, apigen.ScopeRef{Scope: "cluster", Kind: apigen.ScopeKindCluster, Label: "test"}, got.Scope)
	require.Equal(t, apigen.CoverageFunnel{Pods: intPtr(3), Images: 10, Catalogued: 6, FullDetail: 4, FeedsFresh: 2, FeedsTotal: 3}, got.Funnel)
	require.Equal(t, len(got.Gaps), got.TotalGaps)
	require.Equal(t, apigen.Gap{Code: apigen.GapCodeFeedStale, Remedy: apigen.RemedyCodeCheckFeedAccess, What: "kev", Detail: kev.LastError},
		got.Gaps[0])

	codes := map[apigen.GapCode]bool{}
	for _, g := range got.Gaps {
		codes[g.Code] = true
		require.True(t, g.Remedy.Valid(), "%s has remedy %q", g.Code, g.Remedy)
		require.LessOrEqual(t, len([]rune(g.Detail)), 200)
	}
	for _, c := range []apigen.GapCode{apigen.GapCodePending, apigen.GapCodeUnattributedExecutables, apigen.GapCodeCpeOnlyClassifier,
		apigen.GapCodeCatalogFailed, apigen.GapCodeUnresolvableSideloaded, apigen.GapCodeAttestationPartial, apigen.GapCodeUnresolvableAuth,
		apigen.GapCodeNodeAgentMissing} {
		require.True(t, codes[c], "missing %s", c)
	}

	cpe := gapsByCode(t, got.Gaps, apigen.GapCodeCpeOnlyClassifier)[0]
	require.Equal(t, "ghcr.io/example/worker", cpe.What)
	require.Equal(t, "traefik", cpe.Detail)
	require.Equal(t, apigen.RemedyCodeInformational, cpe.Remedy)

	auth := gapsByCode(t, got.Gaps, apigen.GapCodeUnresolvableAuth)[0]
	require.Equal(t, "ghcr.io/example/private", auth.What)
	require.Equal(t, fmt.Sprintf(registry.ReasonUnauthorized, "ghcr.io/example/private"), auth.Detail)
	require.Equal(t, &apigen.ScopeRef{Scope: "image:unknown:ghcr.io/example/private:1.0", Kind: apigen.ScopeKindImage,
		Label: "ghcr.io/example/private"}, auth.Target)
	require.Equal(t, apigen.GapAffects{Workloads: 1, Images: 1}, auth.Affects)
	require.Equal(t, apigen.RemedyCodeAddPullSecret, auth.Remedy)

	require.Equal(t, "catalogue timed out", gapsByCode(t, got.Gaps, apigen.GapCodeCatalogFailed)[0].Detail)

	agent := gapsByCode(t, got.Gaps, apigen.GapCodeNodeAgentMissing)
	require.Len(t, agent, 1, "one gap per node code")
	require.Equal(t, "2 nodes", agent[0].What, "worker-2 is stale and cp-1 never reported")
	require.Equal(t, 2, agent[0].Affects.Nodes)
	require.Nil(t, agent[0].Target)
	require.Equal(t, apigen.RemedyCodeEnableNodeAgent, agent[0].Remedy)

	worker := ok[apigen.Coverage](t, get(t, h, "/api/v1/coverage?scope=workload:Deployment/shop/worker"))
	require.Equal(t, apigen.CoverageFunnel{Pods: intPtr(1), Images: 2, Catalogued: 1, FullDetail: 0, FeedsFresh: 2, FeedsTotal: 3},
		worker.Funnel)
	var wcodes []apigen.GapCode
	for _, g := range worker.Gaps {
		wcodes = append(wcodes, g.Code)
	}
	require.ElementsMatch(t, []apigen.GapCode{apigen.GapCodeFeedStale, apigen.GapCodeUnattributedExecutables,
		apigen.GapCodeCpeOnlyClassifier, apigen.GapCodeCatalogFailed}, wcodes)
	require.Equal(t, len(worker.Gaps), worker.TotalGaps)

	wantProblem(t, get(t, h, "/api/v1/coverage?scope=image:"+webtest.DigestWeb), 400, apigen.ProblemCodeInvalidScope)
}

func intPtr(n int) *int { return &n }

// #15: the cluster rail reads every node group's coverage in one pass. Each figure is the one the
// group's own scope gives, whatever state its host image and members are in: no host image, no
// images row, a failed catalogue, a first match not run yet, a member whose agent never reported or
// is stale, and seen into in full; and the rail's gap marks follow them.
func TestRailGroupCoverage_MatchesPerGroup(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	// Small's agent group keeps worker-1, whose agent reports; worker-2's is stale.
	members := map[string]string{"worker-1": webtest.AgentGroupID, "cp-1": webtest.CP1GroupID}
	add := func(prefix, name string, digest bool, status model.ImageStatus, node string) model.NodeGroup {
		t.Helper()
		id := prefix + strings.Repeat("0", 64-len(prefix))
		g := model.NodeGroup{ID: id, Kind: model.NodeGroupAgent, Name: name, Label: nodegroup.GroupLabel(name, id), Arch: "amd64"}
		if digest {
			g.Digest = nodegroup.GroupDigest(id)
		}
		require.NoError(t, f.Store.PutNodeGroup(ctx, g, webtest.Now))
		if status != "" {
			require.NoError(t, f.Store.UpsertImage(ctx, model.Image{Digest: g.Digest, Repo: model.HostRepo, Platform: "linux/amd64",
				Status: status, Source: "agent", CataloguedAt: webtest.Now}))
		}
		members[node] = id
		return g
	}
	add("a1", "pool-no-digest", false, "", "pool-a-1")
	add("b1", "pool-no-row", true, "", "pool-b-1")
	add("c1", "pool-failed", true, model.ImageCatalogFailed, "pool-c-1")
	unmatched := add("d1", "pool-unmatched", true, model.ImageCatalogued, "pool-d-1")
	require.NoError(t, f.Store.MarkUnmatched(ctx, unmatched.Digest, webtest.Now))
	add("e1", "pool-agentless", true, model.ImageCatalogued, "pool-e-1")
	add("f1", "pool-stale", true, model.ImageCatalogued, "worker-2")
	nodes, err := f.Store.ListNodes(ctx)
	require.NoError(t, err)
	var cp []model.Node
	for _, n := range nodes {
		if n.Name == "cp-1" {
			cp = append(cp, n)
		}
	}
	require.NoError(t, f.Store.ApplyNodeGrouping(ctx, store.NodeGrouping{Members: members, Fallback: nodegroup.FallbackGroups(cp, webtest.Now),
		Now: webtest.Now}))

	keys, batched, perGroup, err := apiserver.New(f.Options()).RailGroupCoverage(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 8)
	require.Equal(t, perGroup, batched)
	got := map[string]store.CoverageFigure{}
	for i, k := range keys {
		got[k] = batched[i]
	}
	for _, k := range []string{"pool-no-digest", "pool-no-row", "pool-failed", "pool-unmatched", webtest.CP1GroupKey} {
		require.Equal(t, store.CoverageFigure{InUse: 1}, got[k], k)
	}
	require.Equal(t, store.CoverageFigure{InUse: 1, SeenInto: 1}, got["pool-agentless"], "its member's agent has not reported")
	require.Equal(t, store.CoverageFigure{InUse: 1, SeenInto: 1}, got["pool-stale"], "its member's agent is stale")
	require.Equal(t, store.CoverageFigure{InUse: 1, SeenInto: 1, Full: 1}, got[webtest.AgentGroupKey])

	card := scopeCard(t, handlerOf(f), "")
	i := slices.IndexFunc(card.Related, func(r apigen.RelatedSection) bool { return r.Id == apigen.RelatedSectionIdNodegroups })
	require.GreaterOrEqual(t, i, 0)
	require.Len(t, card.Related[i].Items, len(keys))
	for _, item := range card.Related[i].Items {
		require.NotNil(t, item.Scope)
		k := strings.TrimPrefix(*item.Scope, "nodegroup:")
		require.Equal(t, got[k].Full < got[k].InUse, item.Gap, k)
	}
}
