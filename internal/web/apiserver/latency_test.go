//go:build bench

package apiserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// latencyBudget is the p95 every list, facet and aggregate operation must stay under on the
// DefaultScale fixture (spec G8).
const latencyBudget = 150 * time.Millisecond

// latencyOp is one API operation and the request targets, below /api/v1, it is measured with: the
// default first, then realistic selections.
type latencyOp struct {
	name     string
	variants []string
}

// scaleAPI builds the DefaultScale fixture in dir and returns the API handler over it.
func scaleAPI(tb testing.TB, dir string) http.Handler {
	tb.Helper()
	f, err := webtest.Scale(tb.Context(), dir+"/ffs.db", webtest.DefaultScale)
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, f.Close()) })
	return apiserver.New(f.Options()).Handler()
}

// serve runs one GET of target (below /api/v1) through h and requires a 200.
func serve(tb testing.TB, h http.Handler, target string) *httptest.ResponseRecorder {
	tb.Helper()
	req := httptest.NewRequestWithContext(tb.Context(), http.MethodGet, apiserver.BaseURL+target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(tb, http.StatusOK, rec.Code, "%s: %s", target, rec.Body.String())
	return rec
}

func decode[T any](tb testing.TB, h http.Handler, target string) T {
	tb.Helper()
	var out T
	require.NoError(tb, json.Unmarshal(serve(tb, h, target).Body.Bytes(), &out), target)
	return out
}

// latencyOps is the operation table over the Scale fixture behind h. The first workload by
// namespace is w, d its image and ns-03 the namespace of the scoped variants.
func latencyOps(tb testing.TB, h http.Handler) []latencyOp {
	tb.Helper()
	const ns = "ns-03"
	first := decode[apigen.WorkloadsPage](tb, h, "/workloads?sort=namespace&limit=1")
	require.NotEmpty(tb, first.Rows)
	wr := first.Rows[0].Workload
	w := wr.Kind + "/" + wr.Namespace + "/" + wr.Name
	detail := decode[apigen.WorkloadDetail](tb, h, "/workloads/"+w)
	require.NotEmpty(tb, detail.Containers)
	require.NotNil(tb, detail.Containers[0].Digest, w)
	d := *detail.Containers[0].Digest
	require.NotNil(tb, detail.BestFix, w)
	fixKey := detail.BestFix.Key

	const findingFacets = "facets=state,priority,fix,signal,ecosystem,namespace,kind"
	page := decode[apigen.FindingsPage](tb, h, "/findings?"+findingFacets)
	require.NotNil(tb, page.Next)
	cursor := *page.Next

	// The advisory with the most open findings.
	var advisory string
	most := -1
	for next := ""; ; {
		target := "/findings?group=advisory&limit=200"
		if next != "" {
			target += "&cursor=" + url.QueryEscape(next)
		}
		groups := decode[apigen.FindingsPage](tb, h, target)
		for _, g := range groups.GroupRows {
			if g.Findings > most {
				advisory, most = g.Key, g.Findings
			}
		}
		if groups.Next == nil {
			break
		}
		next = *groups.Next
	}
	require.NotEmpty(tb, advisory)

	ws, ds, img := "workload:"+w, "image:"+d, "/images/"+url.PathEscape(d)
	const workloadFacets = "facets=kind,namespace,signal,priority,coverage"
	const imageFacets = "facets=status,source,coverage,namespace,priority"
	const packageFacets = "facets=ecosystem,priority"
	return []latencyOp{
		{"getSummary", []string{"/summary", "/summary?scope=namespace:" + ns}},
		{"getScope", []string{"/scope", "/scope?scope=namespace:" + ns, "/scope?scope=" + url.QueryEscape(ws), "/scope?scope=" + url.QueryEscape(ds)}},
		{"getExposure", []string{"/exposure", "/exposure?group=namespace", "/exposure?group=node", "/exposure?expand=not-exposed"}},
		{"listFindings", []string{
			"/findings?" + findingFacets,
			"/findings?priority=urgent,high&" + findingFacets,
			"/findings?signal=exposed&ecosystem=deb&" + findingFacets,
			"/findings?group=advisory",
			"/findings?group=fix",
			"/findings?sort=-epss",
			"/findings?cursor=" + url.QueryEscape(cursor),
			"/findings?scope=" + url.QueryEscape(ws) + "&fixKey=" + url.QueryEscape(fixKey) + "&limit=10",
		}},
		{"listTransitions", []string{"/transitions", "/transitions?scope=namespace:" + ns}},
		{"getAdvisory", []string{"/advisories/" + url.PathEscape(advisory)}},
		{"listWorkloads", []string{
			"/workloads?" + workloadFacets,
			"/workloads?signal=exposed&" + workloadFacets,
			"/workloads?priority=urgent&namespace=" + ns + "&" + workloadFacets,
		}},
		{"getWorkload", []string{"/workloads/" + w}},
		{"listImages", []string{
			"/images?" + imageFacets,
			"/images?coverage=partial&" + imageFacets,
			"/images?priority=urgent&" + imageFacets,
		}},
		{"getImage", []string{img}},
		{"listImagePackages", []string{img + "/packages", img + "/packages?q=pkg-1&ecosystem=deb"}},
		{"listPackages", []string{
			"/packages?" + packageFacets,
			"/packages?ecosystem=npm&" + packageFacets,
			"/packages?priority=urgent&" + packageFacets,
		}},
		{"listNodeGroups", []string{"/nodegroups"}},
		{"getCoverage", []string{"/coverage", "/coverage?scope=namespace:" + ns}},
		{"search", []string{"/search?q=app-1", "/search?q=CVE-2026-1"}},
	}
}

// TestAPILatency_P95 measures every list, facet and aggregate operation in process on the
// DefaultScale fixture: each variant five times to warm up, then 100 requests cycling through the
// variants. Each operation's p95 must be under latencyBudget.
func TestAPILatency_P95(t *testing.T) {
	start := time.Now()
	h := scaleAPI(t, t.TempDir())
	t.Logf("DefaultScale fixture built in %s", time.Since(start).Round(time.Millisecond))
	ops := latencyOps(t, h)

	const measured = 100
	p95s := make([]time.Duration, len(ops))
	t.Logf("%-18s %10s %10s %10s", "op", "p50", "p95", "max")
	for i, op := range ops {
		for _, v := range op.variants {
			for range 5 {
				serve(t, h, v)
			}
		}
		times := make([]time.Duration, measured)
		for j := range times {
			v := op.variants[j%len(op.variants)]
			at := time.Now()
			serve(t, h, v)
			times[j] = time.Since(at)
		}
		slices.Sort(times)
		p95s[i] = times[94]
		t.Logf("%-18s %10s %10s %10s", op.name, times[49].Round(10*time.Microsecond), times[94].Round(10*time.Microsecond),
			times[99].Round(10*time.Microsecond))
	}
	for i, op := range ops {
		require.Less(t, p95s[i], latencyBudget, op.name)
	}
}
