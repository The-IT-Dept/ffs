package apiserver_test

import (
	"encoding/json"
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

// smallFindings names Small's findings F1–F12 by advisory and owner key.
var smallFindings = map[string]string{
	"CVE-2026-0001 Deployment/shop/web": "F1", "CVE-2026-0002 Deployment/shop/web": "F2", "CVE-2026-0006 Deployment/shop/web": "F3",
	"CVE-2026-0004 Deployment/shop/worker": "F4", "CVE-2026-0005 Deployment/shop/worker": "F5",
	"CVE-2026-0007 Deployment/shop/worker": "F6", "CVE-2026-0009 Deployment/shop/worker": "F7",
	"CVE-2026-0001 Deployment/payments/api": "F8", "GO-2026-0010 DaemonSet/ops/node-exporter": "F9",
	"CVE-2026-0008 CronJob/ops/backup": "F10", "CVE-2026-0003 Cluster//test": "F11", "CVE-2026-0011 ContainerRuntime//containerd": "F12",
}

// names returns the F names of rows, sorted.
func names(t *testing.T, rows []apigen.FindingRow) []string {
	t.Helper()
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		n, ok := smallFindings[r.Advisory.Id+" "+r.Workload.Kind+"/"+r.Workload.Namespace+"/"+r.Workload.Name]
		require.True(t, ok, "unknown row %s %+v", r.Advisory.Id, r.Workload)
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

func findingsAt(t *testing.T, h http.Handler, query string) apigen.FindingsPage {
	t.Helper()
	return ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings"+query))
}

// facetPairs maps a facet's values to (count, selected), in the order they came.
type facetPair struct {
	Value    string
	Count    int
	Selected bool
}

func facetPairs(vals []apigen.FacetValue) []facetPair {
	out := make([]facetPair, len(vals))
	for i, v := range vals {
		out[i] = facetPair{v.Value, v.Count, v.Selected}
	}
	return out
}

func TestFindings_DefaultIsOpenEveryPriority(t *testing.T) {
	_, h := newAPI(t)
	rec := get(t, h, "/api/v1/findings")
	got := ok[apigen.FindingsPage](t, rec)
	require.Equal(t, smallOpenTotal, got.Total)
	require.Equal(t, smallOpenTotal, got.Findings)
	require.Zero(t, got.Groups)
	require.Empty(t, got.GroupRows)
	require.Nil(t, got.Next)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	require.JSONEq(t, `{}`, string(raw["facets"]), "facets is an empty object, not null")
	require.JSONEq(t, `[]`, string(raw["groupRows"]))
	require.JSONEq(t, `null`, string(raw["next"]))

	require.Len(t, got.Rows, smallOpenTotal)
	require.Equal(t, "CVE-2026-0001", got.Rows[0].Advisory.Id)
	require.Equal(t, "GO-2026-0010", got.Rows[1].Advisory.Id)
	f1 := got.Rows[0]
	require.Equal(t, []string{"F1"}, names(t, got.Rows[:1]))
	require.Equal(t, "OpenSSL buffer overflow", f1.Advisory.Title)
	require.True(t, f1.Advisory.Kev)
	require.NotNil(t, f1.Advisory.Epss)
	require.InDelta(t, 0.42, *f1.Advisory.Epss, 1e-9)
	require.Equal(t, apigen.WorkloadRef{Scope: "workload:Deployment/shop/web", Kind: "Deployment", Namespace: "shop", Name: "web"}, f1.Workload)
	require.Equal(t, []apigen.Signal{apigen.SignalExposed, apigen.SignalExploited, apigen.SignalEpss}, f1.Signals)
	require.Equal(t, apigen.FixKindUpgrade, f1.Fix.Kind)
	require.Equal(t, "openssl", f1.Packages[0].Name)
	require.Equal(t, apigen.FindingStateOpen, f1.State)
	require.NotNil(t, f1.Published)
	require.True(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Equal(*f1.Published))
	require.Equal(t, apigen.PriorityUrgent, f1.Priority)
	require.Equal(t, apigen.SeverityCritical, f1.Severity)
}

func TestFindings_FacetsExcludeOwnSelection(t *testing.T) {
	_, h := newAPI(t)
	got := findingsAt(t, h, "?priority=urgent&facets=priority,fix,state")
	require.Equal(t, 2, got.Total)
	require.Equal(t, []string{"F1", "F9"}, names(t, got.Rows))
	require.Equal(t, []facetPair{
		{"high", smallOpen.High, false}, {"medium", 3, false}, {"low", 2, false}, {"urgent", 2, true},
	}, facetPairs(got.Facets["priority"]), "counted without the priority selection, by count then value")
	require.Equal(t, []facetPair{{"fixed", 1, false}, {"upgrade", 1, false}, {"none", 0, false}, {"wontfix", 0, false}},
		facetPairs(got.Facets["fix"]))
	require.Equal(t, []facetPair{{"open", 2, true}, {"excepted", 0, false}, {"resolved", 0, false}}, facetPairs(got.Facets["state"]))
	require.Len(t, got.Facets, 3)

	wantProblem(t, get(t, h, "/api/v1/findings?facets=coverage"), 400, apigen.ProblemCodeInvalidParameter)
}

func TestFindings_SignalsAreANDed(t *testing.T) {
	_, h := newAPI(t)
	require.Equal(t, []string{"F1"}, names(t, findingsAt(t, h, "?signal=exposed,exploited").Rows))
	require.Equal(t, []string{"F8", "F9"}, names(t, findingsAt(t, h, "?signal=privileged").Rows))
	wantProblem(t, get(t, h, "/api/v1/findings?signal=bogus"), 400, apigen.ProblemCodeInvalidParameter)
}

func TestFindings_GroupByFix(t *testing.T) {
	_, h := newAPI(t)
	got := findingsAt(t, h, "?group=fix")
	require.Equal(t, smallFixGroups, got.Total)
	require.Equal(t, smallFixGroups, got.Groups)
	require.Equal(t, smallOpenTotal, got.Findings)
	require.Empty(t, got.Rows)
	require.Len(t, got.GroupRows, smallFixGroups)

	first := got.GroupRows[0]
	require.Equal(t, "upgrade:docker.io/library/nginx:1.30.7", first.Key)
	require.NotNil(t, first.Fix)
	require.Equal(t, "1.30.6 → 1.30.7", first.Fix.Label)
	require.Equal(t, "1.30.6 → 1.30.7", first.Label)
	require.Equal(t, apigen.PriorityCounts{Urgent: 1, High: 1}, first.Counts)
	require.NotNil(t, first.Fix.Introduces)
	require.Equal(t, apigen.PriorityCounts{}, *first.Fix.Introduces)
	require.Equal(t, 2, first.Distinct, "two advisories")
	require.NotNil(t, got.GroupRows[1].Fix)
	require.Equal(t, "stdlib go1.24.1 → 1.24.5", got.GroupRows[1].Fix.Label)
	n := len(got.GroupRows)
	require.Equal(t, []string{"none", "wontfix"}, []string{got.GroupRows[n-2].Key, got.GroupRows[n-1].Key})

	byAdvisory := findingsAt(t, h, "?group=advisory")
	i := slices.IndexFunc(byAdvisory.GroupRows, func(r apigen.FindingGroupRow) bool { return r.Key == "CVE-2026-0001" })
	require.GreaterOrEqual(t, i, 0)
	row := byAdvisory.GroupRows[i]
	require.Equal(t, 2, row.Findings)
	require.Equal(t, 2, row.Distinct, "two workloads")
	require.Equal(t, apigen.PriorityCounts{Urgent: 1, High: 1}, row.Counts)
	require.Equal(t, 2, row.Exploited)
	require.Equal(t, "OpenSSL buffer overflow", row.Label)
	require.Nil(t, row.Fix)
}

func TestFindings_PagesWithCursor(t *testing.T) {
	_, h := newAPI(t)
	seen := map[string]bool{}
	query := "?limit=4"
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10)
		got := findingsAt(t, h, query)
		require.LessOrEqual(t, len(got.Rows), 4)
		require.Equal(t, smallOpenTotal, got.Total)
		for _, r := range got.Rows {
			require.False(t, seen[r.Id], "row %s repeated", r.Id)
			seen[r.Id] = true
		}
		if got.Next == nil {
			break
		}
		query = "?limit=4&cursor=" + url.QueryEscape(*got.Next)
	}
	require.Len(t, seen, smallOpenTotal)
}

func TestFindings_ForeignCursorOverHTTP(t *testing.T) {
	_, h := newAPI(t)
	first := findingsAt(t, h, "?limit=1")
	require.NotNil(t, first.Next)
	c := url.QueryEscape(*first.Next)

	wantProblem(t, get(t, h, "/api/v1/findings?limit=1&priority=urgent&cursor="+c), 400, apigen.ProblemCodeInvalidCursor)
	wantProblem(t, get(t, h, "/api/v1/transitions?cursor="+c), 400, apigen.ProblemCodeInvalidCursor)

	second := findingsAt(t, h, "?limit=1&cursor="+c)
	require.Len(t, second.Rows, 1)
	require.NotEqual(t, first.Rows[0].Id, second.Rows[0].Id)
}

func TestFindings_StatesAndScopes(t *testing.T) {
	_, h := newAPI(t)
	resolved := findingsAt(t, h, "?state=resolved")
	require.Equal(t, 1, resolved.Total)
	require.Equal(t, []string{"F7"}, names(t, resolved.Rows))
	require.NotNil(t, resolved.Rows[0].ResolvedAt)
	require.True(t, webtest.Now.Add(-10*24*time.Hour).Equal(*resolved.Rows[0].ResolvedAt))
	require.Equal(t, smallOpenTotal+1, findingsAt(t, h, "?state=open,excepted").Total)

	require.Equal(t, []string{"F4", "F6"}, names(t, findingsAt(t, h, "?scope=workload:Deployment/shop/worker").Rows))
	require.Equal(t, []string{"F8"}, names(t, findingsAt(t, h, "?scope="+url.QueryEscape("image:"+webtest.DigestPayments)).Rows))
	require.Equal(t, []string{"F11", "F12"}, names(t, findingsAt(t, h, "?scope=controlplane").Rows))
	placeholder := findingsAt(t, h, "?scope="+url.QueryEscape("image:"+webtest.DigestPlaceholder))
	require.Zero(t, placeholder.Total)
	require.Empty(t, placeholder.Rows)
	wantProblem(t, get(t, h, "/api/v1/findings?scope=bogus"), 400, apigen.ProblemCodeInvalidScope)
	wantProblem(t, get(t, h, "/api/v1/findings?scope=node:missing"), 404, apigen.ProblemCodeNotFound)

	require.Equal(t, []string{"F2"}, names(t, findingsAt(t, h, "?advisory=GHSA-aaaa-bbbb-cccc").Rows), "found by alias")
	require.Equal(t, []string{"F4", "F6"}, names(t, findingsAt(t, h, "?package=traefik").Rows))
	require.Equal(t, []string{"F8"}, names(t, findingsAt(t, h, "?q=payments").Rows))
	require.Equal(t, []string{"F8"}, names(t, findingsAt(t, h, "?fixKey=rebuild:debian:12").Rows), "F1's action is the upgrade")
	require.Equal(t, []string{"F1", "F2"}, names(t, findingsAt(t, h,
		"?scope=workload:Deployment/shop/web&fixKey="+url.QueryEscape("upgrade:docker.io/library/nginx:1.30.7")).Rows))
	require.Equal(t, []string{"F3"}, names(t, findingsAt(t, h, "?fixKey=none").Rows))
}

func TestTransitions_NewestFirstAndScoped(t *testing.T) {
	_, h := newAPI(t)
	all := ok[apigen.TransitionsPage](t, get(t, h, "/api/v1/transitions"))
	require.Len(t, all.Rows, 4)
	require.Nil(t, all.Next)
	require.True(t, slices.IsSortedFunc(all.Rows, func(a, b apigen.TransitionRow) int { return int(b.Id - a.Id) }), "ids descending")
	t4 := all.Rows[0]
	require.Empty(t, t4.FromState)
	require.Equal(t, apigen.FindingStateOpen, t4.ToState)
	require.Equal(t, apigen.PriorityNone, t4.FromPriority)
	require.Equal(t, apigen.PriorityUrgent, t4.ToPriority)
	require.Equal(t, "NewAdvisory", t4.Trigger)
	require.Equal(t, "CVE-2026-0001", t4.Advisory)
	require.Equal(t, "web", t4.Workload.Name)
	require.True(t, webtest.Now.Add(-2*time.Hour).Equal(t4.At))

	worker := ok[apigen.TransitionsPage](t, get(t, h, "/api/v1/transitions?scope=workload:Deployment/shop/worker"))
	var states []apigen.FindingState
	for _, r := range worker.Rows {
		states = append(states, r.ToState)
	}
	require.Equal(t, []apigen.FindingState{apigen.FindingStateExcepted, apigen.FindingStateResolved, apigen.FindingStateOpen}, states,
		"T3, T2, T1")
	wantProblem(t, get(t, h, "/api/v1/transitions?scope=image:x"), 400, apigen.ProblemCodeInvalidScope)

	var paged []int64
	query := "?limit=1"
	for range 5 {
		page := ok[apigen.TransitionsPage](t, get(t, h, "/api/v1/transitions"+query))
		require.Len(t, page.Rows, 1)
		paged = append(paged, page.Rows[0].Id)
		if page.Next == nil {
			break
		}
		query = "?limit=1&cursor=" + url.QueryEscape(*page.Next)
	}
	require.Equal(t, []int64{all.Rows[0].Id, all.Rows[1].Id, all.Rows[2].Id, all.Rows[3].Id}, paged)
}

// V50: the kind facet tells the cluster-level owners apart from namespaced owners of the same kind:
// the Kubernetes Cluster owner is cluster-level:Cluster, labelled, and a CloudNativePG Cluster is
// Cluster.
func TestFindings_KindFacetSeparatesClusterLevelOwners(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	cnpg := model.OwnerRef{Kind: model.OwnerKindCluster, Namespace: "db", Name: "pg-main"}
	const repo = "ghcr.io/cloudnative-pg/postgresql"
	require.NoError(t, f.Store.ApplyFindings(ctx, []model.Finding{{Fingerprint: model.FindingFingerprint(webtest.ClusterName, cnpg, repo, "CVE-2026-0001"),
		Owner: cnpg, ImageRepo: repo, AdvisoryID: "CVE-2026-0001", Digests: []string{"sha256:" + strings.Repeat("5", 64)},
		Packages: []model.FindingPackage{{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1"}}, Severity: model.SeverityCritical,
		Priority: model.PriorityHigh, State: model.StateOpen, Observed: webtest.Now, Matched: webtest.Now, LastSeen: webtest.Now}}, nil))
	h := handlerOf(f)

	page := ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?facets=kind"))
	kinds := map[string]apigen.FacetValue{}
	for _, v := range page.Facets["kind"] {
		kinds[v.Value] = v
	}
	require.Equal(t, 1, kinds["Cluster"].Count, "the CloudNativePG cluster")
	require.Nil(t, kinds["Cluster"].Label)
	for value, label := range map[string]string{"cluster-level:Cluster": "Kubernetes (control plane)",
		"cluster-level:ContainerRuntime": "Container runtime (control plane)", "cluster-level:Nodes": "Nodes (host packages)"} {
		require.Equal(t, 1, kinds[value].Count, value)
		require.NotNil(t, kinds[value].Label, value)
		require.Equal(t, label, *kinds[value].Label)
	}
	require.Equal(t, 6, kinds["Deployment"].Count, "workload kinds keep their plain value")

	cnpgOnly := ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?kind=Cluster"))
	require.Equal(t, 1, cnpgOnly.Total)
	require.Equal(t, "pg-main", cnpgOnly.Rows[0].Workload.Name)
	k8s := ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?kind=cluster-level:Cluster&facets=kind"))
	require.Equal(t, 1, k8s.Total)
	require.Equal(t, "CVE-2026-0003", k8s.Rows[0].Advisory.Id)
	both := ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?kind=Cluster,cluster-level:Cluster"))
	require.Equal(t, 2, both.Total)
	for _, v := range k8s.Facets["kind"] {
		if v.Value == "cluster-level:Cluster" {
			require.True(t, v.Selected)
		}
	}
}
