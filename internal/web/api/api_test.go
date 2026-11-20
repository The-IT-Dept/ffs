package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/api"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

type doc = map[string]any

func get(t *testing.T, srv *httptest.Server, path string) (int, doc, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	var d doc
	require.NoError(t, json.Unmarshal(b, &d), string(b))
	return res.StatusCode, d, string(b)
}

func seeded(t *testing.T) *httptest.Server {
	t.Helper()
	svc, _ := webtest.Seed(t)
	srv := httptest.NewServer(api.NewHandler(svc))
	t.Cleanup(srv.Close)
	return srv
}

func items(t *testing.T, d doc) []doc {
	t.Helper()
	var out []doc
	for _, v := range d["items"].([]any) {
		out = append(out, v.(doc))
	}
	return out
}

func item(d doc) doc { return d["item"].(doc) }

func ids(t *testing.T, d doc) []string {
	t.Helper()
	var out []string
	for _, it := range items(t, d) {
		out = append(out, it["id"].(string))
	}
	return out
}

func fp(owner model.OwnerRef, repo, adv string) string {
	return model.FindingFingerprint("test", owner, repo, adv)
}

func strs(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

var allPaths = []string{
	"/api/v1/findings", "/api/v1/vulnerabilities", "/api/v1/owners", "/api/v1/images", "/api/v1/nodes", "/api/v1/cluster",
	"/api/v1/suggestions", "/api/v1/exceptions", "/api/v1/feeds", "/api/v1/search?q=php",
	"/api/v1/owners/Deployment/shop/web", "/api/v1/owners/Cluster/-/test", "/api/v1/images/" + webtest.DigestWeb,
	"/api/v1/nodes/node-a", "/api/v1/vulnerabilities/CVE-2026-0001",
	"/api/v1/findings/" + fp(webtest.Web, "docker.io/library/nginx", "CVE-2026-0001"),
}

func TestAPI_EveryResponseHasCluster(t *testing.T) {
	srv := seeded(t)
	for _, p := range append(allPaths, "/api/v1/nodes/nope", "/api/v1/nothing", "/api/v1/findings?priority=severe", "/api/v1/search") {
		_, d, body := get(t, srv, p)
		require.Equal(t, "test", d["cluster"], "%s: %s", p, body)
	}
}

func TestAPI_FindingsFilters(t *testing.T) {
	srv := seeded(t)
	f := map[string]string{
		"F1": fp(webtest.Web, "docker.io/library/nginx", "CVE-2026-0001"),
		"F2": fp(webtest.Web, "docker.io/library/nginx", "CVE-2026-0002"),
		"F3": fp(webtest.Worker, "ghcr.io/example/worker", "CVE-2026-0004"),
		"F4": fp(webtest.Worker, "ghcr.io/example/worker", "CVE-2026-0005"),
		"F5": fp(webtest.Cluster, "kubernetes", "CVE-2026-0003"),
	}
	cases := []struct {
		query string
		want  []string
		total int
	}{
		{"", []string{"F1", "F2", "F5", "F3"}, 4},
		{"?priority=urgent", []string{"F1"}, 1},
		{"?priority=high", []string{"F1", "F2", "F5"}, 3},
		{"?namespace=shop", []string{"F1", "F2", "F3"}, 3},
		{"?owner=Deployment/shop/web", []string{"F1", "F2"}, 2},
		{"?owner=Cluster/-/test", []string{"F5"}, 1},
		{"?advisory=GHSA-aaaa-bbbb-cccc", []string{"F2"}, 1},
		{"?state=excepted", []string{"F4"}, 1},
		{"?state=all", []string{"F1", "F2", "F5", "F3", "F4"}, 5},
		{"?limit=1&offset=1", []string{"F2"}, 4},
	}
	for _, c := range cases {
		code, d, body := get(t, srv, "/api/v1/findings"+c.query)
		require.Equal(t, 200, code, body)
		var want []string
		for _, k := range c.want {
			want = append(want, f[k])
		}
		require.Equal(t, want, ids(t, d), c.query)
		require.EqualValues(t, c.total, d["total"], c.query)
	}

	_, d, _ := get(t, srv, "/api/v1/findings?limit=1&offset=1")
	require.EqualValues(t, 1, d["limit"])
	require.EqualValues(t, 1, d["offset"])
	_, d, _ = get(t, srv, "/api/v1/findings?limit=5000")
	require.EqualValues(t, 1000, d["limit"])
	_, d, _ = get(t, srv, "/api/v1/findings")
	require.EqualValues(t, 100, d["limit"])

	for _, bad := range []string{"?priority=severe", "?state=bogus", "?limit=x", "?offset=-1"} {
		code, d, _ := get(t, srv, "/api/v1/findings"+bad)
		require.Equal(t, 400, code, bad)
		require.NotEmpty(t, d["error"])
		require.Equal(t, "test", d["cluster"])
	}

	_, d, _ = get(t, srv, "/api/v1/findings?priority=urgent")
	it := items(t, d)[0]
	require.Equal(t, "urgent", it["priority"])
	require.Equal(t, true, it["kev"])
	require.Equal(t, []any{"actively exploited (CISA KEV, added 2026-11-02)", "exposed via HTTPRoute shop/web on Gateway public/edge"}, it["reasons"])
	require.Equal(t, "nginx:1.30.7", it["suggestion"].(doc)["target"])
}

func TestAPI_FindingStableID(t *testing.T) {
	srv := seeded(t)
	_, d, _ := get(t, srv, "/api/v1/findings?priority=urgent")
	id := items(t, d)[0]["id"].(string)
	require.Equal(t, fp(webtest.Web, "docker.io/library/nginx", "CVE-2026-0001"), id)

	code, d, _ := get(t, srv, "/api/v1/findings/"+id)
	require.Equal(t, 200, code)
	require.Equal(t, id, item(d)["id"])
	require.Equal(t, "Deployment/shop/web", item(d)["owner"])

	code, _, _ = get(t, srv, "/api/v1/findings/unknown")
	require.Equal(t, 404, code)
}

func TestAPI_Vulnerabilities(t *testing.T) {
	srv := seeded(t)
	_, d, _ := get(t, srv, "/api/v1/vulnerabilities")
	require.Equal(t, []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}, ids(t, d))
	first := items(t, d)[0]
	require.Equal(t, true, first["kev"])
	require.Equal(t, "urgent", first["highestPriority"])
	require.EqualValues(t, 1, first["owners"])

	code, d, _ := get(t, srv, "/api/v1/vulnerabilities/GHSA-aaaa-bbbb-cccc")
	require.Equal(t, 200, code)
	require.Equal(t, "CVE-2026-0002", item(d)["id"])
	require.Len(t, item(d)["findings"], 1)

	code, _, _ = get(t, srv, "/api/v1/vulnerabilities/CVE-1999-0000")
	require.Equal(t, 404, code)
}

func TestAPI_OwnersAndClusterLevelPath(t *testing.T) {
	srv := seeded(t)
	_, d, _ := get(t, srv, "/api/v1/owners/Cluster/-/test")
	require.Equal(t, "Cluster//test", item(d)["id"])
	require.Equal(t, "Cluster/-/test", item(d)["path"])

	_, d, _ = get(t, srv, "/api/v1/owners/Deployment/shop/web")
	require.Equal(t, doc{"urgent": float64(1), "high": float64(1)}, item(d)["counts"])

	_, d, _ = get(t, srv, "/api/v1/owners/Deployment/shop/worker")
	notes := strs(item(d)["coverageNotes"])
	require.Contains(t, notes, "daily, CPE-based coverage only: traefik")
	require.Contains(t, notes, "catalogue timed out")

	_, d, _ = get(t, srv, "/api/v1/owners/CronJob/ops/backup")
	require.Contains(t, strs(item(d)["coverageNotes"]), "bare config digest")

	code, _, _ := get(t, srv, "/api/v1/owners/Deployment/shop/nope")
	require.Equal(t, 404, code)

	_, d, _ = get(t, srv, "/api/v1/owners")
	require.Len(t, items(t, d), 5)
	for _, o := range items(t, d) {
		if o["id"] == "Deployment/shop/worker" {
			require.EqualValues(t, 2, o["images"], "worker and its sidecar")
			require.EqualValues(t, 1, o["imagesCatalogued"], "the sidecar's catalogue failed")
		}
	}
}

func TestAPI_ImagesStatusAndCoverage(t *testing.T) {
	srv := seeded(t)
	_, d, body := get(t, srv, "/api/v1/images")
	require.NotContains(t, body, "clean")
	want := []string{"id", "repo", "platform", "indexDigest", "status", "statusReason", "source", "versionAnnotation",
		"partialCoverage", "coverage", "cataloguedAt", "owners"}
	byID := map[string]doc{}
	for _, it := range items(t, d) {
		keys := make([]string, 0, len(it))
		for k := range it {
			keys = append(keys, k)
		}
		require.ElementsMatch(t, want, keys)
		cov := it["coverage"].(doc)
		require.Contains(t, cov, "notes")
		byID[it["id"].(string)] = it
	}
	require.Len(t, byID, 6)

	u := byID[webtest.DigestUnresolvable]
	require.Equal(t, "unresolvable", u["status"])
	require.Equal(t, "bare config digest", u["statusReason"])
	require.Equal(t, "catalogFailed", byID[webtest.DigestFailed]["status"])

	w := byID[webtest.DigestWeb]
	require.Equal(t, true, w["partialCoverage"])
	require.Equal(t, []string{"2 executables not attributed to any package"}, strs(w["coverage"].(doc)["notes"]))
	require.Equal(t, []string{"Deployment/shop/web"}, strs(w["owners"]))

	wk := byID[webtest.DigestWorker]
	require.Equal(t, true, wk["partialCoverage"])
	require.Contains(t, strs(wk["coverage"].(doc)["notes"]), "daily, CPE-based coverage only: traefik")

	_, d, body = get(t, srv, "/api/v1/images/"+webtest.DigestWeb)
	require.NotContains(t, body, "clean")
	var names []string
	for _, p := range item(d)["packages"].([]any) {
		names = append(names, p.(doc)["name"].(string))
	}
	require.ElementsMatch(t, []string{"openssl", "php-cli"}, names)

	code, _, _ := get(t, srv, "/api/v1/images/sha256:nope")
	require.Equal(t, 404, code)
}

func TestAPI_NodesAndCluster(t *testing.T) {
	srv := seeded(t)
	_, d, _ := get(t, srv, "/api/v1/nodes")
	n := items(t, d)[0]
	require.Equal(t, "Ubuntu 24.04.4 LTS", n["osImage"])
	require.Equal(t, "24.04", n["osEol"].(doc)["cycle"])

	_, d, _ = get(t, srv, "/api/v1/nodes/node-a")
	require.Equal(t, "6.8.0-88-generic", item(d)["kernelVersion"])
	code, _, _ := get(t, srv, "/api/v1/nodes/nope")
	require.Equal(t, 404, code)

	_, d, _ = get(t, srv, "/api/v1/cluster")
	c := item(d)
	require.Equal(t, "", c["distribution"])
	k := c["kubernetes"].([]any)
	require.Len(t, k, 1)
	require.Equal(t, "1.34.2", k[0].(doc)["version"])
	require.EqualValues(t, 1, k[0].(doc)["nodes"])
	require.Equal(t, "kubernetes 1.34 reached end of life 2026-10-27", k[0].(doc)["eol"].(doc)["text"])
	r := c["runtimes"].([]any)
	require.Len(t, r, 1)
	rt := r[0].(doc)
	require.Equal(t, "containerd", rt["name"])
	require.Equal(t, "2.2.1", rt["version"])
	require.EqualValues(t, 1, rt["nodes"])
	require.Equal(t, "containerd 2.2 reached end of life 2026-11-06", rt["eol"].(doc)["text"])
	require.Contains(t, strs(c["coverageNotes"]), "kernel, runc and other bundled components (flannel) are not inventoried")
}

func TestAPI_Suggestions(t *testing.T) {
	srv := seeded(t)
	_, d, _ := get(t, srv, "/api/v1/suggestions")
	its := items(t, d)
	require.Len(t, its, 2)
	require.Equal(t, "Deployment/shop/web", its[0]["owner"])
	require.Equal(t, "nginx:1.30.7", its[0]["target"])
	require.Equal(t, doc{"urgent": float64(1), "high": float64(1)}, its[0]["fixes"])
	require.Equal(t, "fixes 1 urgent, 1 high; introduces none", its[0]["netChange"])

	none := its[1]
	require.Equal(t, "Deployment/shop/worker", none["owner"])
	require.Equal(t, "none", none["tier"])
	require.Equal(t, "", none["target"])
	alt := none["alternatives"].([]any)[0].(doc)
	require.Equal(t, "ghcr.io/example/worker:3.0.0", alt["target"])
	require.Equal(t, "major", alt["tier"])

	// a finding carries its owner's suggestion only when that upgrade fixes it
	_, d, _ = get(t, srv, "/api/v1/findings?owner=Deployment/shop/worker&state=all")
	for _, f := range items(t, d) {
		require.Nil(t, f["suggestion"], f["advisory"])
	}
}

func TestAPI_Exceptions(t *testing.T) {
	srv := seeded(t)
	_, d, _ := get(t, srv, "/api/v1/exceptions")
	its := items(t, d)
	require.Len(t, its, 1)
	require.Equal(t, "shop/accept-risk", its[0]["id"])
	require.Equal(t, "Not reachable in our configuration", its[0]["reason"])
	require.Equal(t, "2027-01-01T00:00:00Z", its[0]["expires"])
	require.Equal(t, []string{"CVE-2026-0005"}, strs(its[0]["advisories"]))
}

func TestAPI_Feeds(t *testing.T) {
	srv := seeded(t)
	_, d, _ := get(t, srv, "/api/v1/feeds")
	stale := map[string]bool{}
	for _, it := range items(t, d) {
		stale[it["name"].(string)] = it["stale"].(bool)
	}
	require.Equal(t, map[string]bool{"osv": false, "kev": true, "eol": false}, stale)
	var haveEOL, haveKEV bool
	for _, a := range d["attribution"].([]any) {
		s := a.(doc)
		haveEOL = haveEOL || (s["name"] == "endoflife.date" && s["licence"] == "MIT")
		haveKEV = haveKEV || (s["feed"] == "kev" && s["licence"] == "CC0-1.0")
	}
	require.True(t, haveEOL && haveKEV)
}

func TestAPI_Search(t *testing.T) {
	srv := seeded(t)
	search := func(q string) doc {
		t.Helper()
		code, d, body := get(t, srv, "/api/v1/search?"+q)
		require.Equal(t, 200, code, body)
		return item(d)
	}

	r := search("q=php")
	pk := r["packages"].([]any)
	require.Len(t, pk, 1)
	require.Equal(t, doc{"name": "php-cli", "version": "8.3.14", "ecosystem": "binary", "owners": []any{"Deployment/shop/web"}}, pk[0])
	require.EqualValues(t, 2, r["uncatalogued"])

	require.Len(t, search("q=php&lt=8.3.15")["packages"], 1)
	require.Empty(t, search("q=php&lt=8.3.14")["packages"])

	require.Equal(t, "CVE-2026-0001", search("q=cve-2026-0001")["advisories"].([]any)[0].(doc)["id"])
	require.Equal(t, "CVE-2026-0002", search("q=aaaa-bbbb")["advisories"].([]any)[0].(doc)["id"])

	img := search("q=nginx")["images"].([]any)
	require.Len(t, img, 1)
	require.Equal(t, webtest.DigestWeb, img[0].(doc)["id"])

	r = search("q=%25")
	require.Empty(t, r["packages"])
	require.Empty(t, r["advisories"])
	require.Empty(t, r["images"])

	code, _, _ := get(t, srv, "/api/v1/search?q=")
	require.Equal(t, 400, code)
}

func TestAPI_SearchVersionFilterBeforeCap(t *testing.T) {
	svc, st := webtest.Seed(t)
	srv := httptest.NewServer(api.NewHandler(svc))
	t.Cleanup(srv.Close)
	existing, err := st.PackagesForImage(t.Context(), webtest.DigestWeb)
	require.NoError(t, err)
	// 60 high versions sort before "6.0.0" as strings, so a SQL LIMIT 50 would drop the match.
	for i := range 60 {
		existing = append(existing, model.Package{Ecosystem: "binary", Name: "bulklib", Version: fmt.Sprintf("50.0.%02d", i),
			Classifier: "bulklib-binary", Path: fmt.Sprintf("/opt/bulk%02d", i)})
	}
	existing = append(existing, model.Package{Ecosystem: "binary", Name: "bulklib", Version: "6.0.0", Classifier: "bulklib-binary", Path: "/opt/low"})
	require.NoError(t, st.PutSBOM(t.Context(), webtest.DigestWeb, nil, existing))

	code, d, body := get(t, srv, "/api/v1/search?q=bulklib&lt=10.0.0")
	require.Equal(t, 200, code, body)
	r := item(d)
	require.Len(t, r["packages"], 1)
	require.Equal(t, false, r["truncated"])

	code, d, body = get(t, srv, "/api/v1/search?q=bulklib")
	require.Equal(t, 200, code, body)
	r = item(d)
	require.Len(t, r["packages"], 50)
	require.Equal(t, true, r["truncated"])
}

func TestAPI_ReadOnly(t *testing.T) {
	srv := seeded(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req, err := http.NewRequestWithContext(t.Context(), m, srv.URL+"/api/v1/findings", strings.NewReader("{}"))
		require.NoError(t, err)
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = res.Body.Close()
		require.Equal(t, http.StatusMethodNotAllowed, res.StatusCode, m)
	}
}

func TestAPI_NeverReturnsSecretMaterial(t *testing.T) {
	srv := seeded(t)
	for _, p := range allPaths {
		_, _, body := get(t, srv, p)
		for _, bad := range []string{"regcred", "pullSecrets", "password", "token"} {
			require.NotContains(t, body, bad, p)
		}
	}
}

func TestAPI_EmptyService(t *testing.T) {
	srv := httptest.NewServer(api.NewHandler(webtest.Empty(t)))
	t.Cleanup(srv.Close)
	for _, p := range []string{"/api/v1/findings", "/api/v1/owners", "/api/v1/images", "/api/v1/cluster", "/api/v1/exceptions", "/api/v1/suggestions"} {
		code, d, body := get(t, srv, p)
		require.Equal(t, 200, code, body)
		require.Equal(t, "test", d["cluster"])
		require.NotContains(t, body, "null", p)
	}
}

// TestAPI_PlaceholderImage is the API side of F45: an unresolvable placeholder ID is addressable.
func TestAPI_PlaceholderImage(t *testing.T) {
	svc, st := webtest.Seed(t)
	webtest.SeedPlaceholder(t, st)
	srv := httptest.NewServer(api.NewHandler(svc))
	t.Cleanup(srv.Close)
	code, d, body := get(t, srv, "/api/v1/images/"+webtest.DigestPlaceholder)
	require.Equal(t, 200, code, body)
	require.Equal(t, webtest.DigestPlaceholder, item(d)["id"])
	require.Equal(t, "unresolvable", item(d)["status"])
	require.Equal(t, []string{"CronJob/ops/report"}, strs(item(d)["owners"]))
}

// TestAPI_ListsDecodeOnlyWhatTheyShow is the regression test for F37: owner counts, the advisory
// list and the image list used to decode every open finding, or every package of every image, on
// each request. A finding and a package the store cannot decode are planted; the lists that do
// not show them still answer, so they no longer read them.
func TestAPI_ListsDecodeOnlyWhatTheyShow(t *testing.T) {
	svc, st := webtest.Seed(t)
	srv := httptest.NewServer(api.NewHandler(svc))
	t.Cleanup(srv.Close)
	// the worker's open medium finding: counted on the lists, decoded only on its own pages
	webtest.ExecSQL(t, st, `UPDATE findings SET data = json_set(data, '$.Packages', 'not a list') WHERE fingerprint = ?`,
		fp(webtest.Worker, "ghcr.io/example/worker", "CVE-2026-0004"))
	// an unclassified package: the image list's coverage note needs only classified ones
	webtest.ExecSQL(t, st, `UPDATE packages SET cpes = 'not json' WHERE name = 'openssl'`)

	code, d, body := get(t, srv, "/api/v1/owners")
	require.Equal(t, 200, code, body)
	for _, o := range items(t, d) {
		if o["id"] == "Deployment/shop/worker" {
			require.Equal(t, doc{"medium": float64(1)}, o["counts"])
		}
	}
	code, d, body = get(t, srv, "/api/v1/vulnerabilities")
	require.Equal(t, 200, code, body)
	require.Equal(t, []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}, ids(t, d))
	medium := items(t, d)[3]
	require.Equal(t, "medium", medium["highestPriority"])
	require.Equal(t, "medium", medium["severity"])
	require.EqualValues(t, 1, medium["owners"])
	require.EqualValues(t, 1, medium["findingCount"])
	require.Equal(t, false, medium["fixAvailable"])
	require.Equal(t, true, items(t, d)[0]["fixAvailable"])
	code, _, body = get(t, srv, "/api/v1/images")
	require.Equal(t, 200, code, body)

	code, _, _ = get(t, srv, "/api/v1/findings?owner=Deployment/shop/worker")
	require.Equal(t, 500, code, "the planted finding is undecodable where it is shown")
}
