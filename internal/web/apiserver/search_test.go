package apiserver_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
)

func hitOf(t *testing.T, res apigen.SearchResult, kind apigen.SearchHitKind, id string) apigen.SearchHit {
	t.Helper()
	for _, h := range res.Hits {
		if h.Kind == kind && h.Id == id {
			return h
		}
	}
	require.Failf(t, "hit missing", "%s %s in %+v", kind, id, res.Hits)
	return apigen.SearchHit{}
}

func TestSearch_JumpsAcrossKinds(t *testing.T) {
	_, h := newAPI(t)

	res := ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=web"))
	require.Equal(t, "web", res.Query)
	require.False(t, res.Truncated)
	web := hitOf(t, res, apigen.SearchHitKindWorkload, "Deployment/shop/web")
	require.Equal(t, "web", web.Label)
	require.NotNil(t, web.Scope)
	require.Equal(t, "workload:Deployment/shop/web", *web.Scope)
	require.NotNil(t, web.Worst)
	require.Equal(t, apigen.PriorityUrgent, *web.Worst)

	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=CVE-2026-0001"))
	adv := hitOf(t, res, apigen.SearchHitKindAdvisory, "CVE-2026-0001")
	require.Nil(t, adv.Scope)
	require.False(t, res.Truncated)

	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=shop"))
	ns := hitOf(t, res, apigen.SearchHitKindNamespace, "shop")
	require.NotNil(t, ns.Scope)
	require.Equal(t, "namespace:shop", *ns.Scope)
	require.False(t, res.Truncated)

	wantProblem(t, get(t, h, "/api/v1/search"), 400, apigen.ProblemCodeInvalidParameter)
	wantProblem(t, get(t, h, "/api/v1/search?q="+strings.Repeat("a", 101)), 400, apigen.ProblemCodeInvalidParameter)
}
