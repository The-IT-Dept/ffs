package apiserver_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func workloadRow(t *testing.T, rows []apigen.WorkloadRow, name string) apigen.WorkloadRow {
	t.Helper()
	i := slices.IndexFunc(rows, func(r apigen.WorkloadRow) bool { return r.Workload.Name == name })
	require.GreaterOrEqual(t, i, 0, "no row %s", name)
	return rows[i]
}

func workloadNames(rows []apigen.WorkloadRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Workload.Name
	}
	return out
}

func TestWorkloads_ListsEntitiesWithCounts(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.WorkloadsPage](t, get(t, h, "/api/v1/workloads"))
	require.Equal(t, 7, got.Total)
	require.Len(t, got.Rows, 7)
	require.Equal(t, "web", got.Rows[0].Workload.Name)
	require.Equal(t, "node-exporter", got.Rows[1].Workload.Name, "riskiest first")
	require.Nil(t, got.Next)

	coredns := workloadRow(t, got.Rows, "coredns")
	require.Equal(t, apigen.PriorityCounts{}, coredns.Counts)
	require.Equal(t, apigen.CoverageClassFull, coredns.CoverageClass)
	require.Nil(t, coredns.BestFix)

	web := workloadRow(t, got.Rows, "web")
	require.Equal(t, apigen.WorkloadRef{Scope: "workload:Deployment/shop/web", Kind: "Deployment", Namespace: "shop", Name: "web"}, web.Workload)
	require.NotNil(t, web.Pods)
	require.Equal(t, 2, *web.Pods)
	require.True(t, web.Exposed)
	require.Equal(t, apigen.CoverageFigure{InUse: 2, SeenInto: 1, Full: 1}, web.Coverage)
	require.Equal(t, apigen.CoverageClassPartial, web.CoverageClass)
	require.NotNil(t, web.BestFix)
	require.Equal(t, apigen.FixKindUpgrade, web.BestFix.Kind)
	require.Equal(t, "1.30.6 → 1.30.7", web.BestFix.Label)
	require.NotNil(t, web.ManagedBy)
	require.Equal(t, "helm", web.ManagedBy.Tool)
	require.Equal(t, apigen.PriorityCounts{Urgent: 1, High: 1, Medium: 1}, web.Counts)
	require.Equal(t, 3, web.Open)

	report := workloadRow(t, got.Rows, "report")
	require.NotNil(t, report.Pods)
	require.Equal(t, 0, *report.Pods, "known to have no pods")
	require.Equal(t, apigen.CoverageClassNone, report.CoverageClass)
	require.True(t, report.NotRunning)

	for _, r := range got.Rows {
		require.NotContains(t, []string{"Cluster", "ContainerRuntime", "Nodes"}, r.Workload.Kind)
	}
}

func TestWorkloads_FacetsAndFilters(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.WorkloadsPage](t, get(t, h, "/api/v1/workloads?signal=exposed&facets=kind,namespace,signal,priority,coverage"))
	require.Equal(t, 2, got.Total)
	require.ElementsMatch(t, []string{"web", "node-exporter"}, workloadNames(got.Rows))
	require.Len(t, got.Facets, 5)
	signal := map[string]facetPair{}
	for _, p := range facetPairs(got.Facets["signal"]) {
		signal[p.Value] = p
	}
	require.Equal(t, facetPair{"exposed", 2, true}, signal["exposed"], "counted over all 7 workloads, without the signal selection")
	require.Equal(t, facetPair{"not_running", 2, false}, signal["not_running"])
	require.Equal(t, facetPair{"privileged", 2, false}, signal["privileged"])
	require.Equal(t, facetPair{"sa_power", 1, false}, signal["sa_power"])

	require.Equal(t, []string{"report"}, workloadNames(ok[apigen.WorkloadsPage](t, get(t, h, "/api/v1/workloads?coverage=none")).Rows))
	require.Equal(t, []string{"worker"}, workloadNames(ok[apigen.WorkloadsPage](t, get(t, h, "/api/v1/workloads?q=work")).Rows))
	require.Equal(t, 3, ok[apigen.WorkloadsPage](t, get(t, h, "/api/v1/workloads?scope=namespace:ops")).Total)
	wantProblem(t, get(t, h, "/api/v1/workloads?scope=image:x"), 400, apigen.ProblemCodeInvalidScope)
	wantProblem(t, get(t, h, "/api/v1/workloads?sort=bogus"), 400, apigen.ProblemCodeInvalidParameter)
}

func TestWorkload_Detail(t *testing.T) {
	_, h := newAPI(t)
	rec := get(t, h, "/api/v1/workloads/Deployment/shop/web")
	got := ok[apigen.WorkloadDetail](t, rec)
	require.Equal(t, "web", got.ServiceAccount)
	require.NotNil(t, got.Pods)
	require.Equal(t, 2, *got.Pods)
	require.True(t, got.Exposed)
	require.Equal(t, []apigen.ExposureEdge{{Entry: apigen.EntryKindGateway, EntryName: "gateway/public", Listener: "https",
		Hostname: "shop.example.com", Route: "HTTPRoute shop/web", Service: "shop/web:8080", Internal: false}}, got.Exposure)

	str := func(s string) *string { return &s }
	catalogued, pending := apigen.ImageStatusCatalogued, apigen.ImageStatusPending
	full, none := apigen.CoverageClassFull, apigen.CoverageClassNone
	require.Equal(t, []apigen.WorkloadContainer{
		{Name: "app", Kind: "container", Image: "docker.io/library/nginx:1.30.6", Repo: "docker.io/library/nginx",
			Digest: str(webtest.DigestWeb), Platform: str("linux/amd64"), Status: &catalogued, Coverage: &full},
		{Name: "proxy", Kind: "container", Image: "ghcr.io/example/proxy:2.0", Repo: "ghcr.io/example/proxy",
			Digest: str(webtest.DigestProxy), Platform: str("linux/amd64"), Status: &pending, Coverage: &none},
	}, got.Containers)
	require.Equal(t, apigen.PriorityCounts{Urgent: 1, High: 1, Medium: 1}, got.Counts)
	require.Len(t, got.Upgrades, 1)
	require.Equal(t, "1.30.7", got.Upgrades[0].ToTag)
	require.Contains(t, got.CoverageNotes, "image not catalogued yet: ghcr.io/example/proxy")
	require.Equal(t, apigen.CoverageFigure{InUse: 2, SeenInto: 1, Full: 1}, got.Coverage)
	require.NotNil(t, got.BestFix)
	require.Equal(t, "upgrade:docker.io/library/nginx:1.30.7", got.BestFix.Key)
	require.NotContains(t, rec.Body.String(), "regcred", "pull-secret names are never served")

	worker := ok[apigen.WorkloadDetail](t, get(t, h, "/api/v1/workloads/Deployment/shop/worker"))
	require.True(t, worker.SaPower)
	require.Equal(t, []string{"can read Secrets in namespace shop"}, worker.SaReasons)
	require.Equal(t, 1, worker.Excepted)
	require.Empty(t, worker.Upgrades[0].ToTag, "tier none: no upgrade in the current line")
	require.Contains(t, worker.CoverageNotes, "daily, CPE-based coverage only: traefik")
	require.Contains(t, worker.CoverageNotes, "catalogue timed out")

	cluster := ok[apigen.WorkloadDetail](t, get(t, h, "/api/v1/workloads/Cluster/-/test"))
	require.Equal(t, apigen.WorkloadRef{Scope: "workload:Cluster//test", Kind: "Cluster", Namespace: "", Name: "test"}, cluster.Workload)
	p := wantProblem(t, get(t, h, "/api/v1/workloads/Deployment/shop/nope"), 404, apigen.ProblemCodeNotFound)
	require.Contains(t, *p.Detail, "Deployment/shop/nope")
}

func TestWorkloads_PodsNullBeforeInventoryFlush(t *testing.T) {
	f := webtest.Open(t)
	f.Pods = nil
	h := apiserver.New(f.Options()).Handler()

	rec := get(t, h, "/api/v1/workloads")
	list := ok[apigen.WorkloadsPage](t, rec)
	for _, r := range list.Rows {
		require.Nil(t, r.Pods, r.Workload.Name)
	}
	var raw struct{ Rows []map[string]json.RawMessage }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	require.JSONEq(t, `null`, string(raw.Rows[0]["pods"]))

	rec = get(t, h, "/api/v1/workloads/Deployment/shop/web")
	require.Nil(t, ok[apigen.WorkloadDetail](t, rec).Pods)
	var detail map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &detail))
	require.JSONEq(t, `null`, string(detail["pods"]))
}
