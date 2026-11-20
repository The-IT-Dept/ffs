package apiserver_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/web/apigen"
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
