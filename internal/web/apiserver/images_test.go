package apiserver_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func imageRow(t *testing.T, rows []apigen.ImageRow, digest string) apigen.ImageRow {
	t.Helper()
	i := slices.IndexFunc(rows, func(r apigen.ImageRow) bool { return r.Digest == digest })
	require.GreaterOrEqual(t, i, 0, "no row %s", digest)
	return rows[i]
}

func TestImages_ListAndFacets(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.ImagesPage](t, get(t, h, "/api/v1/images?facets=status,source,coverage,namespace,priority"))
	require.Equal(t, 10, got.Total)
	require.Len(t, got.Facets, 5)
	status := map[string]int{}
	for _, v := range got.Facets["status"] {
		status[v.Value] = v.Count
	}
	require.Equal(t, map[string]int{"catalogued": 6, "pending": 1, "unresolvable": 2, "catalogFailed": 1}, status)

	partial := ok[apigen.ImagesPage](t, get(t, h, "/api/v1/images?coverage=partial"))
	var digests []string
	for _, r := range partial.Rows {
		digests = append(digests, r.Digest)
	}
	require.ElementsMatch(t, []string{webtest.DigestWorker, webtest.DigestAttested}, digests)

	for digest, want := range map[string][]apigen.GapCode{
		webtest.DigestWorker:       {apigen.GapCodeUnattributedExecutables, apigen.GapCodeCpeOnlyClassifier},
		webtest.DigestAttested:     {apigen.GapCodeAttestationPartial},
		webtest.DigestFailed:       {apigen.GapCodeCatalogFailed},
		webtest.DigestProxy:        {apigen.GapCodePending},
		webtest.DigestUnresolvable: {apigen.GapCodeUnresolvableSideloaded},
		webtest.DigestWeb:          {}, // php-cli has a fast-path mapping
		webtest.DigestCoreDNS:      {},
	} {
		require.Equal(t, want, imageRow(t, got.Rows, digest).Gaps, digest)
	}
	web := imageRow(t, got.Rows, webtest.DigestWeb)
	require.Equal(t, "docker.io/library/nginx", web.Repo)
	require.Equal(t, "linux/amd64", web.Platform)
	require.Equal(t, "registry", web.Source)
	require.Equal(t, 1, web.Workloads)
	require.Equal(t, apigen.PriorityCounts{Urgent: 1, High: 1, Medium: 1}, web.Counts)
}

func TestImages_PlaceholderIDWithSlashesRoundTrips(t *testing.T) {
	f, h := newAPI(t)
	const id = webtest.DigestPlaceholder
	require.Contains(t, id, "/")
	list := ok[apigen.ImagesPage](t, get(t, h, "/api/v1/images?q=private"))
	require.Len(t, list.Rows, 1)
	require.Equal(t, id, list.Rows[0].Digest)
	require.Equal(t, apigen.ImageStatusUnresolvable, list.Rows[0].Status)
	require.Equal(t, []apigen.GapCode{apigen.GapCodeUnresolvableAuth}, list.Rows[0].Gaps)

	// The production chain as well: the guards and the outer router keep the segment whole.
	guarded := web.Handler(f.Config, web.Handlers{API: h})
	viaGuards := func(target string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec
	}
	for _, seg := range []string{url.PathEscape(id), "unknown%3Aghcr.io%2Fexample%2Fprivate%3A1.0"} {
		img := ok[apigen.ImageDetail](t, get(t, h, "/api/v1/images/"+seg))
		require.Equal(t, id, img.Digest, seg)
		require.Equal(t, []apigen.WorkloadRef{{Scope: "workload:CronJob/ops/report", Kind: "CronJob", Namespace: "ops", Name: "report"}},
			img.UsedBy, seg)
		require.Equal(t, []apigen.GapCode{apigen.GapCodeUnresolvableAuth}, img.Coverage.Gaps, seg)
		require.Equal(t, apigen.CoverageClassNone, img.Coverage.Class, seg)
		pkgs := ok[apigen.ImagePackagesPage](t, get(t, h, "/api/v1/images/"+seg+"/packages"))
		require.Zero(t, pkgs.Total, seg)
		require.Empty(t, pkgs.Rows, seg)

		require.Equal(t, id, ok[apigen.ImageDetail](t, viaGuards("/api/v1/images/"+seg)).Digest, seg)
		require.Zero(t, ok[apigen.ImagePackagesPage](t, viaGuards("/api/v1/images/"+seg+"/packages")).Total, seg)
	}
	wantProblem(t, get(t, h, "/api/v1/images/"+id), 404, apigen.ProblemCodeNotFound)
}

func TestImage_Detail(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.ImageDetail](t, get(t, h, "/api/v1/images/"+webtest.DigestWeb))
	require.Equal(t, []string{"docker.io/library/nginx:1.30.6"}, got.Tags)
	str := func(s string) *string { return &s }
	require.Equal(t, apigen.SbomInfo{Source: "registry", Tool: str("syft"), ToolVersion: str("1.57.2")}, got.Sbom)
	require.ElementsMatch(t, []apigen.EcosystemCount{{Ecosystem: "deb", Packages: 2}, {Ecosystem: "binary", Packages: 1}}, got.Ecosystems)
	require.Equal(t, apigen.PriorityCounts{Urgent: 1, High: 1, Medium: 1}, got.Counts)
	require.Equal(t, 2, got.Fixable)
	require.Equal(t, []apigen.WorkloadRef{{Scope: "workload:Deployment/shop/web", Kind: "Deployment", Namespace: "shop", Name: "web"}}, got.UsedBy)
	require.Len(t, got.Upgrades, 1)
	require.Equal(t, "1.30.7", got.Upgrades[0].ToTag)
	require.NotEmpty(t, got.Notable)
	require.Equal(t, "php-cli", got.Notable[0].Name, "classifier-found packages first")
	require.Equal(t, "openssl", got.Notable[1].Name, "then by findings")
	require.Equal(t, apigen.ImageCoverage{Class: apigen.CoverageClassFull, Notes: []string{}, CpeOnly: []string{}, Gaps: []apigen.GapCode{}},
		got.Coverage)
	i := slices.IndexFunc(got.Eol, func(e apigen.EOL) bool { return e.Product == "debian" && e.Cycle == "12" })
	require.GreaterOrEqual(t, i, 0, "debian 12 lifecycle: %+v", got.Eol)

	worker := ok[apigen.ImageDetail](t, get(t, h, "/api/v1/images/"+webtest.DigestWorker))
	require.Equal(t, apigen.ImageCoverage{Class: apigen.CoverageClassPartial, UnattributedExecutables: 2,
		Notes: []string{"2 executables not attributed to any package"}, CpeOnly: []string{"traefik"},
		Gaps: []apigen.GapCode{apigen.GapCodeUnattributedExecutables, apigen.GapCodeCpeOnlyClassifier}}, worker.Coverage)
	require.Empty(t, worker.Upgrades[0].ToTag)

	wantProblem(t, get(t, h, "/api/v1/images/sha256:"+strings.Repeat("0", 64)), 404, apigen.ProblemCodeNotFound)
}

func TestImagePackages_SearchAndEcosystemFacet(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.ImagePackagesPage](t, get(t, h, "/api/v1/images/"+webtest.DigestWeb+"/packages?q=ssl"))
	require.Equal(t, 1, got.Total)
	require.Len(t, got.Rows, 1)
	require.Equal(t, "openssl", got.Rows[0].Name)
	require.Equal(t, "3.0.15-1~deb12u1", got.Rows[0].Version)
	require.Equal(t, 1, got.Rows[0].Findings)
	require.Equal(t, apigen.PriorityUrgent, got.Rows[0].Worst)
	require.ElementsMatch(t, []facetPair{{"deb", 2, false}, {"binary", 1, false}}, facetPairs(got.Facets["ecosystem"]))

	binary := ok[apigen.ImagePackagesPage](t, get(t, h, "/api/v1/images/"+webtest.DigestWeb+"/packages?ecosystem=binary"))
	require.Len(t, binary.Rows, 1)
	require.Equal(t, "php-cli", binary.Rows[0].Name)
	require.NotNil(t, binary.Rows[0].Classifier)
	require.Equal(t, "php-cli-binary", *binary.Rows[0].Classifier)
	require.ElementsMatch(t, []facetPair{{"deb", 2, false}, {"binary", 1, true}}, facetPairs(binary.Facets["ecosystem"]))

	page := ok[apigen.ImagePackagesPage](t, get(t, h, "/api/v1/images/"+webtest.DigestWeb+"/packages?limit=1"))
	require.NotNil(t, page.Next)
	wantProblem(t, get(t, h, "/api/v1/images/"+webtest.DigestPayments+"/packages?limit=1&cursor="+url.QueryEscape(*page.Next)),
		400, apigen.ProblemCodeInvalidCursor)
	wantProblem(t, get(t, h, "/api/v1/images/sha256:"+strings.Repeat("0", 64)+"/packages"), 404, apigen.ProblemCodeNotFound)
}
