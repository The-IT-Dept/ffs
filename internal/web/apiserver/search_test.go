package apiserver_test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
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

func hitIDs(res apigen.SearchResult) []string {
	out := []string{}
	for _, h := range res.Hits {
		out = append(out, string(h.Kind)+":"+h.Id)
	}
	return out
}

// V57: counts in hit details agree with their number.
func TestSearch_CountsArePlural(t *testing.T) {
	_, h := newAPI(t)
	res := ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=pay"))
	require.Equal(t, "1 workload", *hitOf(t, res, apigen.SearchHitKindNamespace, "payments").Detail)
	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=shop"))
	require.Equal(t, "2 workloads", *hitOf(t, res, apigen.SearchHitKindNamespace, "shop").Detail)
	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=ubuntu"))
	require.Equal(t, "1 node", *hitOf(t, res, apigen.SearchHitKindNodegroup, webtest.CP1GroupKey).Detail)
	require.Equal(t, "2 nodes", *hitOf(t, res, apigen.SearchHitKindNodegroup, webtest.AgentGroupKey).Detail)
}

// V60: hits starting with the query come first, the kinds taking turns, and truncated says when a
// kind had more than it was given.
func TestSearch_PrefixFirstKindsInterleavedAndTruncated(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	for i := 1; i <= 10; i++ {
		require.NoError(t, f.Store.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "ops",
			Name: fmt.Sprintf("kube-app-%02d", i)}, UpdatedAt: webtest.Now}))
	}
	nodes, err := f.Store.ListNodes(ctx)
	require.NoError(t, err)
	extra := nodes[0]
	extra.Name = "kube-node-1"
	require.NoError(t, f.Store.ReplaceNodes(ctx, append(nodes, extra)))
	h := handlerOf(f)

	res := ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=kube"))
	require.True(t, res.Truncated, "ten workloads match and eight are asked for")
	require.Equal(t, []string{"controlplane:test", "workload:Deployment/ops/kube-app-01", "namespace:kube-system", "node:kube-node-1",
		"workload:Deployment/ops/kube-app-02"}, hitIDs(res)[:5], "the control plane (Kubernetes), then each kind in turn")
	require.LessOrEqual(t, len(res.Hits), 20)

	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=kube-node"))
	require.False(t, res.Truncated)
	require.Equal(t, []string{"node:kube-node-1"}, hitIDs(res))

	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=app-0"))
	require.Equal(t, "workload:Deployment/ops/kube-app-01", hitIDs(res)[0], "contains matches follow when no label starts with the query")
	require.True(t, res.Truncated, "nine workloads contain app-0")
}

// V61: synthetic digests are never image hits, a package only node groups hold opens the node
// group, and the control plane and Nodes can be found.
func TestSearch_ClusterLevelHitsAndHostPackages(t *testing.T) {
	_, h := newAPI(t)
	for _, q := range []string{"containerd", "kubernetes", "host", "nginx"} {
		res := ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q="+q))
		for _, hit := range res.Hits {
			if hit.Kind == apigen.SearchHitKindImage {
				require.True(t, strings.HasPrefix(hit.Id, "sha256:"), "%s: image hit %s", q, hit.Id)
			}
		}
	}

	res := ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=control"))
	cp := hitOf(t, res, apigen.SearchHitKindControlplane, webtest.ClusterName)
	require.Equal(t, "Control plane", cp.Label)
	require.NotNil(t, cp.Scope)
	require.Equal(t, "controlplane", *cp.Scope)
	require.Equal(t, "Kubernetes 1.34.2", *cp.Detail)
	require.Equal(t, apigen.PriorityHigh, *cp.Worst)
	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=containerd"))
	hitOf(t, res, apigen.SearchHitKindControlplane, webtest.ClusterName)

	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=nodes"))
	nodes := hitOf(t, res, apigen.SearchHitKindNodes, webtest.ClusterName)
	require.Equal(t, "Nodes", nodes.Label)
	require.Equal(t, "3 nodes", *nodes.Detail)
	require.Nil(t, nodes.Scope)
	require.Equal(t, apigen.PriorityHigh, *nodes.Worst)

	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=linux-image"))
	group := hitOf(t, res, apigen.SearchHitKindNodegroup, webtest.AgentGroupKey)
	require.Equal(t, "linux-image-6.8.0-88-generic 6.8.0-88.89 · host package", *group.Detail)
	require.Equal(t, "nodegroup:"+webtest.AgentGroupKey, *group.Scope)
	for _, hit := range res.Hits {
		require.NotEqual(t, apigen.SearchHitKindPackage, hit.Kind, "a host-only package opens its node group")
	}

	res = ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=openssl"))
	hitOf(t, res, apigen.SearchHitKindPackage, "deb/openssl")
	for _, hit := range res.Hits {
		require.NotEqual(t, apigen.SearchHitKindNodegroup, hit.Kind, "openssl is also in container images")
	}
}

// #8: the Control plane and Nodes pages are hits of their own kinds, never workload hits with
// cluster-level owner keys.
func TestSearch_PageHitsHaveTheirOwnKinds(t *testing.T) {
	_, h := newAPI(t)
	for q, want := range map[string]apigen.SearchHitKind{
		"control": apigen.SearchHitKindControlplane, "kubernetes": apigen.SearchHitKindControlplane,
		"containerd": apigen.SearchHitKindControlplane, "nodes": apigen.SearchHitKindNodes, "host packages": apigen.SearchHitKindNodes,
	} {
		res := ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q="+url.QueryEscape(q)))
		hitOf(t, res, want, webtest.ClusterName) // the page is a hit of its own kind
		for _, other := range res.Hits {
			if other.Kind != apigen.SearchHitKindWorkload {
				continue
			}
			for _, key := range []string{webtest.Cluster.Key(), webtest.Runtime.Key(), webtest.Nodes.Key()} {
				require.NotEqual(t, key, other.Id, "%s: a cluster-level owner is not a workload hit", q)
			}
		}
	}
}
