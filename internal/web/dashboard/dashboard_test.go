package dashboard_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web"
	"github.com/the-it-dept/ffs/internal/web/api"
	"github.com/the-it-dept/ffs/internal/web/dashboard"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func serve(t *testing.T, svc *api.Service) *httptest.Server {
	t.Helper()
	d, err := dashboard.New(svc)
	require.NoError(t, err)
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	return srv
}

func seeded(t *testing.T) *httptest.Server {
	t.Helper()
	svc, _ := webtest.Seed(t)
	return serve(t, svc)
}

func get(t *testing.T, srv *httptest.Server, path string, status int) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, status, res.StatusCode, path)
	return string(b)
}

func contains(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		require.Contains(t, body, w)
	}
}

func TestDashboard_NeedsAttention(t *testing.T) {
	body := get(t, seeded(t), "/", 200)
	shop, cluster := strings.Index(body, "Deployment shop/web"), strings.Index(body, "Cluster test")
	require.GreaterOrEqual(t, shop, 0)
	require.Greater(t, cluster, shop)
	contains(t, body, "CVE-2026-0001", "actively exploited (CISA KEV, added 2026-11-02)",
		"exposed via HTTPRoute shop/web on Gateway public/edge", "nginx:1.30.7", "fixes 1 urgent, 1 high; introduces none")
	require.NotContains(t, body, "CVE-2026-0004")
}

func TestDashboard_NeedsAttentionEmpty(t *testing.T) {
	contains(t, get(t, serve(t, webtest.Empty(t)), "/", 200), "No urgent or high findings in 0 catalogued images.")
}

func TestDashboard_Workloads(t *testing.T) {
	contains(t, get(t, seeded(t), "/workloads", 200), "shop/web", "shop/worker", "ops/backup", "Not running", "Cluster test")
}

func TestDashboard_Images(t *testing.T) {
	body := get(t, seeded(t), "/images", 200)
	contains(t, body, "Unresolvable", "bare config digest", "Catalogue failed", "catalogue timed out", "Partial coverage")
}

func TestDashboard_ImageDetail(t *testing.T) {
	srv := seeded(t)
	contains(t, get(t, srv, "/images/"+webtest.DigestWeb, 200), "openssl", "3.0.15-1~deb12u1", "php-cli", "8.3.14",
		"2 executables not attributed to any package")
	contains(t, get(t, srv, "/images/"+webtest.DigestWorker, 200), "daily, CPE-based coverage only: traefik")
	contains(t, get(t, srv, "/images/sha256:nope", 404), "does not exist")
}

func TestDashboard_Owner(t *testing.T) {
	srv := seeded(t)
	contains(t, get(t, srv, "/owners/Deployment/shop/web", 200), "HTTPRoute shop/web on Gateway public/edge", "nginx",
		"CVE-2026-0001", "CVE-2026-0002")
	get(t, srv, "/owners/Cluster/-/test", 200)
	contains(t, get(t, srv, "/owners/Deployment/shop/worker", 200), "daily, CPE-based coverage only: traefik", "catalogue timed out")
	get(t, srv, "/owners/Deployment/shop/nope", 404)
}

func TestDashboard_GoStdlibGrouped(t *testing.T) {
	svc, st := webtest.Seed(t)
	webtest.SeedGoStdlib(t, st)
	body := get(t, serve(t, svc), "/owners/Deployment/tools/gotool", 200)
	require.Equal(t, 1, strings.Count(body, "Go 1.22.3 standard library: 3 advisories, fixed in Go 1.22.12"))
	start := strings.Index(body, "Go 1.22.3 standard library")
	end := start + strings.Index(body[start:], "</tr>")
	for _, id := range []string{"GO-2024-0001", "GO-2024-0002", "GO-2024-0003"} {
		require.Equal(t, 1, strings.Count(body, id), id)
		require.Contains(t, body[start:end], id)
	}
}

func TestDashboard_Vulnerabilities(t *testing.T) {
	srv := seeded(t)
	contains(t, get(t, srv, "/vulnerabilities", 200), "CVE-2026-0001", "KEV")
	contains(t, get(t, srv, "/vulnerabilities/GHSA-aaaa-bbbb-cccc", 200), "CVE-2026-0002", "shop/web")
	contains(t, get(t, srv, "/advisories/CVE-2026-0001", 200), "CVE-2026-0001")
	get(t, srv, "/vulnerabilities/CVE-0000-0000", 404)
}

func TestDashboard_Cluster(t *testing.T) {
	body := get(t, seeded(t), "/cluster", 200)
	contains(t, body, "1.34.2", "kubernetes 1.34 reached end of life 2026-10-27", "Ubuntu 24.04.4 LTS",
		"containerd 2.2 reached end of life 2026-11-06",
		"kernel, runc and other bundled components (flannel) are not inventoried", `href="/nodes/node-a"`)
}

func TestDashboard_NodeDetail(t *testing.T) {
	srv := seeded(t)
	contains(t, get(t, srv, "/nodes/node-a", 200), "6.8.0-88-generic", "v1.34.2", "containerd://2.2.1", "amd64")
	get(t, srv, "/nodes/nope", 404)
}

func TestDashboard_Excepted(t *testing.T) {
	contains(t, get(t, seeded(t), "/excepted", 200), "CVE-2026-0005", "shop/accept-risk", "Not reachable in our configuration")
}

func TestDashboard_Feeds(t *testing.T) {
	body := get(t, seeded(t), "/feeds", 200)
	rows := strings.Split(body, "<tr>")
	var kev, osv string
	for _, r := range rows {
		switch {
		case strings.HasPrefix(r, "<td>kev</td>"):
			kev = r
		case strings.HasPrefix(r, "<td>osv</td>"):
			osv = r
		}
	}
	require.Contains(t, kev, "Stale")
	require.NotEmpty(t, osv)
	require.NotContains(t, osv, "Stale")
	for _, s := range api.Sources {
		contains(t, body, strings.ReplaceAll(s.Name, "&", "&amp;"), s.URL)
		require.Contains(t, body, escape(s.Licence))
	}
	contains(t, body, "ffs fetches these sources at runtime and does not redistribute them.")
}

func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func TestDashboard_Search(t *testing.T) {
	contains(t, get(t, seeded(t), "/search?q=php", 200), "php-cli", "8.3.14", "shop/web",
		"2 images are not catalogued, so this answer may be incomplete.")
}

func TestDashboard_EscapesFeedText(t *testing.T) {
	contains(t, get(t, seeded(t), "/vulnerabilities/CVE-2026-0002", 200), "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestDashboard_CopyRules(t *testing.T) {
	svc, st := webtest.Seed(t)
	webtest.SeedGoStdlib(t, st)
	srv := serve(t, svc)
	needle := "anx" + "iety"
	for _, p := range []string{"/", "/workloads", "/images", "/images/" + webtest.DigestWeb, "/owners/Deployment/shop/web",
		"/owners/Deployment/tools/gotool", "/vulnerabilities", "/vulnerabilities/CVE-2026-0002", "/cluster", "/nodes/node-a",
		"/excepted", "/feeds", "/search?q=php", "/nope"} {
		status := 200
		if p == "/nope" {
			status = 404
		}
		body := get(t, srv, p, status)
		lower := strings.ToLower(body)
		for _, bad := range []string{needle, "clean", "<script"} {
			require.NotContains(t, lower, bad, p)
		}
		contains(t, body, `<form action="/search" method="get">`, `name="q"`)
	}
}

func TestDashboard_StaticAssetAndReadOnly(t *testing.T) {
	svc, _ := webtest.Seed(t)
	d, err := dashboard.New(svc)
	require.NoError(t, err)
	srv := httptest.NewServer(d)
	defer srv.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/assets/style.css", nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, 200, res.StatusCode)
	require.Equal(t, "text/css; charset=utf-8", res.Header.Get("Content-Type"))

	rec := httptest.NewRecorder()
	post := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	post.Host = "localhost:8080"
	web.NewServer(config.Default(), http.NotFoundHandler(), d).Server.Handler.ServeHTTP(rec, post)
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestDashboard_TierNoneSuggestion is the regression test for F39: a suggestion with tier none has
// no target, and the landing page rendered "<strong></strong> … 1.30.6 to" and "fixes none" while
// the major alternative that does fix the findings appeared nowhere.
func TestDashboard_TierNoneSuggestion(t *testing.T) {
	svc, st := webtest.Seed(t)
	const repo = "docker.io/library/nginx"
	require.NoError(t, st.PutSuggestion(t.Context(), webtest.Web.Key(), model.Suggestion{
		Repo: repo, FromTag: "1.30.6", Tier: model.TierNone, EOL: "debian 12 reached end of life 2026-06-10",
		Notes: []string{"no upgrade path in this repository"}, ComputedAt: webtest.Now,
		Alternatives: []model.Suggestion{{Repo: repo, FromTag: "1.30.6", ToTag: "2.0.0", Tier: model.TierMajor,
			Fixes:    map[model.Priority]int{model.PriorityUrgent: 1, model.PriorityHigh: 1},
			FixedIDs: []string{"CVE-2026-0001", "CVE-2026-0002"}}},
	}, nil))
	srv := serve(t, svc)
	for _, p := range []string{"/", "/owners/Deployment/shop/web"} {
		body := get(t, srv, p, 200)
		require.NotContains(t, body, "<strong></strong>", p)
		require.NotContains(t, body, "1.30.6 to <", p)
		require.NotContains(t, body, "fixes none", p)
		contains(t, body, "No upgrade in the current line fixes these findings", "debian 12 reached end of life 2026-06-10",
			"no upgrade path in this repository", "nginx:2.0.0", "major", "fixes 1 urgent, 1 high; introduces none")
	}
}

func TestDashboard_SeedTierNoneOnOwnerPage(t *testing.T) {
	body := get(t, seeded(t), "/owners/Deployment/shop/worker", 200)
	contains(t, body, "No upgrade in the current line fixes these findings", "ghcr.io/example/worker:3.0.0", "fixes 1 medium; introduces none")
	require.NotContains(t, body, "<strong></strong>")
}

// TestDashboard_PlaceholderImage is the regression test for F45: placeholder IDs contain "/", and
// the single-segment route answered "That page does not exist" for exactly the blind-spot images.
func TestDashboard_PlaceholderImage(t *testing.T) {
	svc, st := webtest.Seed(t)
	webtest.SeedPlaceholder(t, st)
	srv := serve(t, svc)
	href := `href="/images/` + webtest.DigestPlaceholder + `"`
	contains(t, get(t, srv, "/images", 200), href)
	contains(t, get(t, srv, "/owners/CronJob/ops/report", 200), href)
	body := get(t, srv, "/images/"+webtest.DigestPlaceholder, 200)
	contains(t, body, "Unresolvable", "registry refused the tag lookup", "CronJob ops/report")
	require.NotContains(t, body, "does not exist")
}

// TestDashboard_PagesDecodeOnlyWhatTheyShow is the dashboard side of F37: the landing page,
// Workloads and Vulnerabilities used to decode every open finding on each load.
func TestDashboard_PagesDecodeOnlyWhatTheyShow(t *testing.T) {
	svc, st := webtest.Seed(t)
	srv := serve(t, svc)
	webtest.ExecSQL(t, st, `UPDATE findings SET data = json_set(data, '$.Packages', 'not a list') WHERE advisory_id = 'CVE-2026-0004'`)
	webtest.ExecSQL(t, st, `UPDATE packages SET cpes = 'not json' WHERE name = 'openssl'`)
	contains(t, get(t, srv, "/", 200), "CVE-2026-0001")
	contains(t, get(t, srv, "/workloads", 200), "shop/worker")
	contains(t, get(t, srv, "/vulnerabilities", 200), "CVE-2026-0004")
	contains(t, get(t, srv, "/images", 200), "Partial coverage")
}

// TestDashboard_NeverReadsAllClearWhenBlind is the regression test for F38: with feeds stale or
// never synced and images not catalogued, every page used to read as if nothing were wrong.
func TestDashboard_NeverReadsAllClearWhenBlind(t *testing.T) {
	// a fresh install: three feeds that never synced, nothing catalogued
	body := get(t, serve(t, webtest.Empty(t)), "/", 200)
	require.NotContains(t, body, "Nothing needs attention")
	contains(t, body, "Incomplete data", "Feed eol has never synced", "Feed kev has never synced", "Feed osv has never synced",
		`href="/feeds"`, "No urgent or high findings in 0 catalogued images.")

	// the seed: kev is 30 h old against 24 h, and three of the five container images are not catalogued
	svc, st := webtest.Seed(t)
	webtest.SeedPlaceholder(t, st)
	srv := serve(t, svc)
	body = get(t, srv, "/", 200)
	contains(t, body, "Feed kev last synced 2026-11-17 18:00 UTC, more than 24h ago", "3 of 5 images in use are not catalogued",
		`href="/images"`)
	require.NotContains(t, body, "Feed osv")
	require.Less(t, strings.Index(body, "Incomplete data"), strings.Index(body, "Deployment shop/web"), "health leads the page")

	// only the healthy part remains: the all-clear names how many images it covers
	webtest.ExecSQL(t, st, `UPDATE findings SET state = 'resolved' WHERE priority >= 3`)
	contains(t, get(t, srv, "/", 200), "No urgent or high findings in 2 catalogued images.")

	// a pending image and a digest with no image row are named on the owner page
	webtest.ExecSQL(t, st, `UPDATE images SET status = 'pending' WHERE digest = ?`, webtest.DigestWorker)
	require.NoError(t, st.UpsertOwner(t.Context(), model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "fresh"},
		Containers: []model.ContainerUse{{Name: "app", Kind: model.ContainerRegular, ImageRef: "ghcr.io/example/fresh:1.0",
			Repo: "ghcr.io/example/fresh", Digest: "sha256:" + strings.Repeat("f", 64)}}}))
	body = get(t, srv, "/owners/Deployment/shop/fresh", 200)
	contains(t, body, "image not catalogued yet: ghcr.io/example/fresh", "No open findings; see Coverage for what was not inventoried.")
	contains(t, get(t, srv, "/owners/Deployment/shop/worker", 200), "image not catalogued yet: ghcr.io/example/worker")

	// Workloads shows how many of each workload's images are catalogued
	body = get(t, srv, "/workloads", 200)
	contains(t, body, "Images catalogued")
	row := func(name string) string {
		t.Helper()
		i := strings.Index(body, name)
		require.GreaterOrEqual(t, i, 0, name)
		return body[i : i+strings.Index(body[i:], "</tr>")]
	}
	require.Contains(t, row("shop/fresh"), "0 of 1")
	require.Contains(t, row("shop/worker"), "0 of 2")
	require.Contains(t, row("shop/web"), "1 of 1")

	// an advisory with no open finding carries the caveat
	require.NoError(t, st.UpsertAdvisory(t.Context(), model.Advisory{ID: "CVE-2026-0099", Title: "Not matched anywhere", Observed: webtest.Now}))
	body = get(t, srv, "/vulnerabilities/CVE-2026-0099", 200)
	contains(t, body, "No open findings for this advisory in the catalogued images.", "5 images in use are not catalogued, so this answer may be incomplete.")
}

// TestDashboard_FindingTimes is the regression test for F44: G3 says every finding shows when the
// advisory was published, when ffs saw it and when it matched; no dashboard page showed them.
func TestDashboard_FindingTimes(t *testing.T) {
	svc, st := webtest.Seed(t)
	webtest.ExecSQL(t, st, `UPDATE findings SET state = 'excepted', data = json_set(data, '$.State', 'excepted') WHERE advisory_id = 'CVE-2026-0001'`)
	srv := serve(t, svc)
	times := []string{"Published / seen / matched", "Published 2026-10-01 00:00 UTC", "Seen by ffs 2026-11-18 21:00 UTC",
		"Matched 2026-11-18 22:00 UTC"}
	contains(t, get(t, srv, "/owners/Deployment/shop/web", 200), times...)
	contains(t, get(t, srv, "/vulnerabilities/CVE-2026-0002", 200), "Published / seen / matched", "Matched 2026-11-19 00:00 UTC")
	contains(t, get(t, srv, "/excepted", 200), times...)
	// the advisory header: published, and first seen by ffs
	require.NoError(t, st.UpsertAdvisory(t.Context(), model.Advisory{ID: "CVE-2026-0002", Published: webtest.Now.Add(-48 * time.Hour)}))
	contains(t, get(t, srv, "/vulnerabilities/CVE-2026-0002", 200), "Published 2026-11-17 00:00 UTC; first seen by ffs 2026-11-19 00:00 UTC.")
	contains(t, get(t, srv, "/", 200), "Published / seen / matched", "Matched 2026-11-19 00:00 UTC")
}
