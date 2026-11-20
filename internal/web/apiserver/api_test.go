package apiserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func TestAPI_EveryEndpointEnvelopeAndNoSecrets(t *testing.T) {
	f, h := newAPI(t)
	paths := []string{
		"/summary", "/scope",
		"/scope?scope=namespace:shop", "/scope?scope=workload:Deployment/shop/web", "/scope?scope=image:" + webtest.DigestWeb,
		"/scope?scope=nodegroup:" + webtest.AgentGroupID, "/scope?scope=node:worker-1", "/scope?scope=controlplane",
		"/exposure", "/exposure?group=namespace", "/exposure?group=node",
		"/findings?facets=state,priority,fix,signal,ecosystem,namespace,kind", "/transitions", "/advisories/CVE-2026-0001",
		"/workloads", "/workloads/Deployment/shop/web", "/images", "/images/" + webtest.DigestWeb,
		"/images/" + webtest.DigestWeb + "/packages", "/packages", "/nodegroups", "/nodegroups/" + webtest.AgentGroupID,
		"/nodes/worker-1", "/coverage", "/feeds", "/exceptions", "/settings", "/search?q=web",
	}
	stamped := func(rec *httptest.ResponseRecorder, path string) {
		t.Helper()
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), path)
		require.Equal(t, "test", body["cluster"], path)
		require.Equal(t, "2026-11-19T00:00:00Z", body["generatedAt"], path)
		require.NotContains(t, rec.Body.String(), "regcred", path)
		require.NotContains(t, rec.Body.String(), "ullSecret", path)
	}
	for _, p := range paths {
		rec := get(t, h, "/api/v1"+p)
		require.Equal(t, http.StatusOK, rec.Code, "%s: %s", p, rec.Body.String())
		require.Equal(t, "application/json", rec.Header().Get("Content-Type"), p)
		stamped(rec, p)
	}
	for _, p := range []string{"/api/v1/findings?cursor=x", "/api/v1/nope"} {
		rec := get(t, h, p)
		require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"), p)
		stamped(rec, p)
	}

	srv := web.Handler(f.Config, web.Handlers{API: h})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/summary", nil)
	req.Host = "rebind.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusMisdirectedRequest, rec.Code)
	require.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain"), rec.Header().Get("Content-Type"))
	require.NotContains(t, rec.Body.String(), "test", "the 421 does not name the cluster")
}

func TestAPI_AggregatesNeverDecodeFindings(t *testing.T) {
	f := webtest.Open(t)
	// F6 is the worker's won't-fix finding, so it is never a best fix's sample.
	f6 := model.FindingFingerprint(webtest.ClusterName, webtest.Worker, "ghcr.io/example/worker", "CVE-2026-0007")
	webtest.ExecSQL(t, f.Store, `UPDATE findings SET data = json_set(data, '$.Reasons', 'not a list') WHERE fingerprint = ?`, f6)
	h := handlerOf(f)
	for _, p := range []string{"/summary", "/scope", "/scope?scope=" + url.QueryEscape("workload:Deployment/shop/worker"), "/exposure",
		"/exposure?group=namespace", "/coverage", "/workloads", "/findings?facets=priority&group=advisory"} {
		rec := get(t, h, "/api/v1"+p)
		require.Equal(t, http.StatusOK, rec.Code, "%s: %s", p, rec.Body.String())
	}
	wantProblem(t, get(t, h, "/api/v1/findings?scope=workload:Deployment/shop/worker"), http.StatusInternalServerError,
		apigen.ProblemCodeInternal)
}
