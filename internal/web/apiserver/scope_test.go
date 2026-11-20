package apiserver_test

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func scopeCard(t *testing.T, h http.Handler, query string) apigen.ScopeCard {
	t.Helper()
	return ok[apigen.ScopeCard](t, get(t, h, "/api/v1/scope"+query))
}

func viewIDs(c apigen.ScopeCard) []apigen.ViewId {
	var out []apigen.ViewId
	for _, v := range c.Views {
		out = append(out, v.Id)
	}
	return out
}

func viewOf(t *testing.T, c apigen.ScopeCard, id apigen.ViewId) apigen.ViewCount {
	t.Helper()
	for _, v := range c.Views {
		if v.Id == id {
			return v
		}
	}
	require.Failf(t, "view missing", "%s in %v", id, viewIDs(c))
	return apigen.ViewCount{}
}

func relatedIDs(c apigen.ScopeCard) []apigen.RelatedSectionId {
	var out []apigen.RelatedSectionId
	for _, r := range c.Related {
		out = append(out, r.Id)
	}
	return out
}

func crumbs(c apigen.ScopeCard) []string {
	out := []string{}
	for _, b := range c.Breadcrumbs {
		out = append(out, b.Scope)
	}
	return out
}

func TestScope_RailPerKind(t *testing.T) {
	_, h := newAPI(t)

	c := scopeCard(t, h, "")
	require.Equal(t, "test", c.Title)
	require.Equal(t, "Kubernetes 1.34.2 · 3 nodes · 4 namespaces", c.Summary)
	require.Equal(t, []string{"test"}, c.Clusters)
	require.True(t, c.Trust.Settings)
	require.Empty(t, c.Breadcrumbs)
	require.Equal(t, []apigen.ViewId{apigen.ViewIdExposure, apigen.ViewIdVulnerabilities, apigen.ViewIdWorkloads, apigen.ViewIdImages,
		apigen.ViewIdPackages, apigen.ViewIdNodes, apigen.ViewIdCoverage}, viewIDs(c))
	require.Equal(t, []apigen.RelatedSectionId{apigen.RelatedSectionIdNamespaces, apigen.RelatedSectionIdNodegroups,
		apigen.RelatedSectionIdControlplane}, relatedIDs(c))
	require.Equal(t, 2, *viewOf(t, c, apigen.ViewIdExposure).Count)
	require.True(t, viewOf(t, c, apigen.ViewIdVulnerabilities).Gap, "not every image is seen into in full")
	require.True(t, viewOf(t, c, apigen.ViewIdNodes).Gap, "two agents are not reporting")
	require.Equal(t, apigen.CoverageFigure{InUse: 10, SeenInto: 6, Full: 4}, c.Trust.Coverage)
	ns := c.Related[0]
	require.Equal(t, "shop", ns.Items[0].Label, "worst first")
	require.Equal(t, apigen.PriorityUrgent, ns.Items[0].Worst)

	c = scopeCard(t, h, "?scope=namespace:shop")
	require.Equal(t, "shop", c.Title)
	require.Equal(t, "2 workloads · 1 urgent · 1 exposed", c.Summary)
	require.Equal(t, []string{"cluster"}, crumbs(c))
	require.False(t, c.Trust.Settings)
	require.Equal(t, []apigen.ViewId{apigen.ViewIdExposure, apigen.ViewIdVulnerabilities, apigen.ViewIdImages, apigen.ViewIdPackages},
		viewIDs(c))
	require.Equal(t, []apigen.RelatedSectionId{apigen.RelatedSectionIdWorkloads}, relatedIDs(c))

	c = scopeCard(t, h, "?scope=workload:Deployment/shop/web")
	require.Equal(t, "web", c.Title)
	require.Equal(t, "2 replicas · Helm web · exposed · SA web", c.Summary)
	require.Equal(t, []string{"cluster", "namespace:shop"}, crumbs(c))
	require.Equal(t, []apigen.ViewId{apigen.ViewIdFindings, apigen.ViewIdUpgrades, apigen.ViewIdExposure, apigen.ViewIdRbac,
		apigen.ViewIdHistory}, viewIDs(c))
	require.Equal(t, []apigen.RelatedSectionId{apigen.RelatedSectionIdContainers, apigen.RelatedSectionIdSiblings}, relatedIDs(c))
	require.Nil(t, viewOf(t, c, apigen.ViewIdRbac).Count)
	require.Equal(t, 1, *viewOf(t, c, apigen.ViewIdUpgrades).Count)
	require.Equal(t, 1, *viewOf(t, c, apigen.ViewIdExposure).Count)
	require.Equal(t, []string{"app", "proxy"}, []string{c.Related[0].Items[0].Label, c.Related[0].Items[1].Label})
	require.Equal(t, "worker", c.Related[1].Items[0].Label)

	c = scopeCard(t, h, "?scope=image:"+webtest.DigestWeb+"&from=workload:Deployment/shop/web")
	require.Equal(t, "docker.io/library/nginx", c.Title)
	require.Equal(t, "docker.io/library/nginx · aaaaaaaaaaaa · amd64", c.Summary)
	require.Equal(t, []string{"cluster", "namespace:shop", "workload:Deployment/shop/web"}, crumbs(c))
	require.Equal(t, "web", c.Breadcrumbs[2].Label)
	require.Equal(t, "registry", *c.Trust.SbomSource)
	require.Equal(t, "syft 1.57.2", *c.Trust.SbomTool)
	require.Equal(t, 0, *c.Trust.Unattributed)
	require.Equal(t, []apigen.ViewId{apigen.ViewIdFindings, apigen.ViewIdPackages, apigen.ViewIdUpgrades, apigen.ViewIdSbom}, viewIDs(c))
	require.Equal(t, []apigen.RelatedSectionId{apigen.RelatedSectionIdUsedBy, apigen.RelatedSectionIdNotablePackages}, relatedIDs(c))
	require.Equal(t, []string{"cluster"}, crumbs(scopeCard(t, h, "?scope=image:"+webtest.DigestWeb)))

	c = scopeCard(t, h, "?scope=nodegroup:"+webtest.AgentGroupID)
	require.Equal(t, "ubuntu-24.04-k6.8.0-88-3f9c1a", c.Title)
	require.Equal(t, "2 nodes · kernel 6.8.0-88 · containerd 2.2.1", c.Summary)
	require.Equal(t, []apigen.ViewId{apigen.ViewIdFindings, apigen.ViewIdHostPackages, apigen.ViewIdKernel, apigen.ViewIdCachedImages,
		apigen.ViewIdMembers}, viewIDs(c))
	require.Equal(t, 2, *viewOf(t, c, apigen.ViewIdHostPackages).Count)
	require.Equal(t, []apigen.RelatedSectionId{apigen.RelatedSectionIdMembers}, relatedIDs(c))

	c = scopeCard(t, h, "?scope=node:worker-2")
	require.Equal(t, "worker-2", c.Title)
	require.Equal(t, "ubuntu-24.04-k6.8.0-88-3f9c1a · Ready · agent stale", c.Summary)
	require.Equal(t, []apigen.RelatedSectionId{apigen.RelatedSectionIdMembers}, relatedIDs(c))
	require.Equal(t, []string{"cluster", "nodegroup:" + webtest.AgentGroupKey}, crumbs(c))
	require.Equal(t, "worker-1", c.Related[0].Items[0].Label, "the other members")
	require.Len(t, c.Related[0].Items, 1)

	cp := scopeCard(t, h, "?scope=nodegroup:"+webtest.CP1GroupID)
	require.Nil(t, viewOf(t, cp, apigen.ViewIdHostPackages).Count)
	require.True(t, viewOf(t, cp, apigen.ViewIdHostPackages).Gap)
	require.True(t, viewOf(t, cp, apigen.ViewIdKernel).Gap)

	c = scopeCard(t, h, "?scope=controlplane")
	require.Equal(t, "Control plane", c.Title)
	require.Equal(t, "Kubernetes 1.34.2 · containerd 2.2.1", c.Summary)
	require.Equal(t, []string{"cluster"}, crumbs(c))
	require.Equal(t, []apigen.ViewId{apigen.ViewIdFindings, apigen.ViewIdUpgrades}, viewIDs(c))
	require.Equal(t, 2, *viewOf(t, c, apigen.ViewIdFindings).Count)

	wantProblem(t, get(t, h, "/api/v1/scope?scope=image:"+webtest.DigestWeb+"&from=namespace:shop"), 400, apigen.ProblemCodeInvalidScope)
	wantProblem(t, get(t, h, "/api/v1/scope?scope=workload:Deployment/shop/missing"), 404, apigen.ProblemCodeNotFound)
}

// memberDetails maps a card's members items by label to their detail and gap.
func memberDetails(t *testing.T, c apigen.ScopeCard) map[string]string {
	t.Helper()
	i := slices.IndexFunc(c.Related, func(r apigen.RelatedSection) bool { return r.Id == apigen.RelatedSectionIdMembers })
	require.GreaterOrEqual(t, i, 0, "members section")
	out := map[string]string{}
	for _, it := range c.Related[i].Items {
		require.Nil(t, it.Count, "a member has no count")
		require.NotNil(t, it.Detail)
		out[it.Label] = fmt.Sprintf("%s gap=%t", *it.Detail, it.Gap)
	}
	return out
}

// TestScope_NodeRailCachedImagesAndMembers pins the node rail's cachedImages count (the node's
// cached images only while its agent is reporting or stale, else 0 with a gap, as on the node
// page) and the members items' "agent <state>" detail.
func TestScope_NodeRailCachedImagesAndMembers(t *testing.T) {
	f, h := newAPI(t)

	cached := func(c apigen.ScopeCard) string {
		v := viewOf(t, c, apigen.ViewIdCachedImages)
		require.NotNil(t, v.Count)
		return fmt.Sprintf("%d gap=%t", *v.Count, v.Gap)
	}

	c := scopeCard(t, h, "?scope=node:worker-1")
	require.Equal(t, "1 gap=false", cached(c), "a reporting agent's cached image")
	require.Equal(t, map[string]string{"worker-2": "agent stale gap=true"}, memberDetails(t, c))

	cachedNginx := []model.NodeImage{{Digest: webtest.DigestWeb, Names: []string{"docker.io/library/nginx:1.30.6"}, Kind: "manifest",
		Source: "status"}}
	require.NoError(t, f.Store.ReplaceNodeImages(t.Context(), "worker-2", cachedNginx))
	c = scopeCard(t, h, "?scope=node:worker-2")
	require.Equal(t, "1 gap=false", cached(c), "a stale agent's cache is still shown")
	require.Equal(t, map[string]string{"worker-1": "agent reporting gap=false"}, memberDetails(t, c))

	// cp-1's agent never reported, so a cached-image row it holds is not shown, as on the node page.
	require.NoError(t, f.Store.ReplaceNodeImages(t.Context(), "cp-1", cachedNginx))
	c = scopeCard(t, h, "?scope=node:cp-1")
	require.True(t, strings.HasSuffix(c.Summary, " · Ready · agent never"), c.Summary)
	require.Equal(t, "0 gap=true", cached(c), "no live agent: zero and a gap")
	require.Empty(t, ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/cp-1")).CachedImages, "the node page agrees")

	c = scopeCard(t, h, "?scope=nodegroup:"+webtest.AgentGroupID)
	require.Equal(t, map[string]string{"worker-1": "agent reporting gap=false", "worker-2": "agent stale gap=true"}, memberDetails(t, c))
}

type totaled struct {
	Total int `json:"total"`
}

func TestScope_ViewCountsMatchExplorerTotals(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	worker, image := "workload:Deployment/shop/worker", "image:"+webtest.DigestWeb
	count := func(h http.Handler, scope string, id apigen.ViewId) int {
		t.Helper()
		v := viewOf(t, scopeCard(t, h, "?scope="+url.QueryEscape(scope)), id)
		require.NotNil(t, v.Count, "%s %s", scope, id)
		return *v.Count
	}
	total := func(h http.Handler, path string) int {
		t.Helper()
		return ok[totaled](t, get(t, h, path)).Total
	}
	check := func(stage string) (workerFindings, workerHistory int) {
		t.Helper()
		h := handlerOf(f)
		require.Equal(t, total(h, "/api/v1/findings"), count(h, "cluster", apigen.ViewIdVulnerabilities), stage)
		require.Equal(t, total(h, "/api/v1/workloads"), count(h, "cluster", apigen.ViewIdWorkloads), stage)
		require.Equal(t, total(h, "/api/v1/images"), count(h, "cluster", apigen.ViewIdImages), stage)
		require.Equal(t, total(h, "/api/v1/packages"), count(h, "cluster", apigen.ViewIdPackages), stage)

		require.Equal(t, total(h, "/api/v1/findings?scope=namespace:shop"), count(h, "namespace:shop", apigen.ViewIdVulnerabilities), stage)
		require.Equal(t, total(h, "/api/v1/images?scope=namespace:shop"), count(h, "namespace:shop", apigen.ViewIdImages), stage)
		require.Equal(t, total(h, "/api/v1/packages?scope=namespace:shop"), count(h, "namespace:shop", apigen.ViewIdPackages), stage)

		workerFindings = count(h, worker, apigen.ViewIdFindings)
		require.Equal(t, total(h, "/api/v1/findings?scope="+worker), workerFindings, stage)
		ts := ok[apigen.TransitionsPage](t, get(t, h, "/api/v1/transitions?limit=200&scope="+worker))
		recent := 0
		for _, tr := range ts.Rows {
			if !tr.At.Before(webtest.Now.Add(-30 * 24 * time.Hour)) {
				recent++
			}
		}
		workerHistory = count(h, worker, apigen.ViewIdHistory)
		require.Equal(t, recent, workerHistory, stage)

		require.Equal(t, total(h, "/api/v1/findings?scope="+url.QueryEscape(image)), count(h, image, apigen.ViewIdFindings), stage)
		require.Equal(t, total(h, "/api/v1/images/"+webtest.DigestWeb+"/packages"), count(h, image, apigen.ViewIdPackages), stage)

		ng := "nodegroup:" + webtest.AgentGroupID
		require.Equal(t, total(h, "/api/v1/findings?scope="+ng), count(h, ng, apigen.ViewIdFindings), stage)
		return workerFindings, workerHistory
	}

	findings, history := check("fixture")
	require.Equal(t, 2, findings, "F4 and F6")
	require.Equal(t, 3, history, "F7 opened 20 days ago and resolved 10 days ago; F5 excepted a day ago")

	require.NoError(t, f.Store.PutSuggestion(ctx, webtest.Worker.Key(), model.Suggestion{Repo: "ghcr.io/example/worker", FromTag: "2.1.0",
		ToTag: "2.1.1", Tier: model.TierPatch, Fixes: map[model.Priority]int{model.PriorityMedium: 1}, FixedIDs: []string{"CVE-2026-0004"},
		ComputedAt: webtest.Now}, nil))
	check("PutSuggestion")
	require.NoError(t, f.Store.DeleteSuggestions(ctx, webtest.Web.Key(), []string{"docker.io/library/nginx"}))
	check("DeleteSuggestions")

	f4fp := model.FindingFingerprint(webtest.ClusterName, webtest.Worker, "ghcr.io/example/worker", "CVE-2026-0004")
	stored, err := f.Store.FindingsByFingerprint(ctx, []string{f4fp})
	require.NoError(t, err)
	f4 := stored[f4fp]
	require.Equal(t, model.StateOpen, f4.State)
	at := webtest.Now
	f4.State, f4.ResolvedAt = model.StateResolved, &at
	require.NoError(t, f.Store.ApplyFindings(ctx, []model.Finding{f4}, []model.Transition{{Fingerprint: f4fp, Owner: webtest.Worker,
		AdvisoryID: f4.AdvisoryID, FromState: model.StateOpen, ToState: model.StateResolved, FromPriority: model.PriorityMedium,
		ToPriority: model.PriorityMedium, Trigger: model.TriggerInventoryChange, At: at}}))
	findings2, history2 := check("ApplyFindings resolves F4")
	require.Equal(t, findings-1, findings2)
	require.Equal(t, history+1, history2)

	_, err = f.Store.PruneResolved(ctx, webtest.Now)
	require.NoError(t, err)
	check("PruneResolved")
}
