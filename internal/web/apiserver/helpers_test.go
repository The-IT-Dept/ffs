package apiserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// Small's open findings, and its fix groups (spec decisions 3 and 16), host finding F13 included.
var smallOpen = apigen.PriorityCounts{Urgent: 2, High: 4, Medium: 3, Low: 2}

const (
	smallOpenTotal = 11
	smallFixGroups = 10
)

// newAPI opens Small and returns it with the API handler over it.
func newAPI(t testing.TB) (*webtest.Fixture, http.Handler) {
	t.Helper()
	f := webtest.Open(t)
	return f, apiserver.New(f.Options()).Handler()
}

// handlerOf is the API handler over f, after a test changed it.
func handlerOf(f *webtest.Fixture) http.Handler { return apiserver.New(f.Options()).Handler() }

func get(t testing.TB, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ok decodes a 200 JSON body, after checking that it names the cluster and the fixture's time.
func ok[T any](t testing.TB, rec *httptest.ResponseRecorder) T {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var env apigen.Envelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	require.Equal(t, webtest.ClusterName, env.Cluster)
	require.True(t, webtest.Now.Equal(env.GeneratedAt), "generatedAt %s", env.GeneratedAt)
	var out T
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

// wantProblem checks that rec is a problem document with status and code, stamped like every
// response, and returns it.
func wantProblem(t testing.TB, rec *httptest.ResponseRecorder, status int, code apigen.ProblemCode) apigen.Problem {
	t.Helper()
	require.Equal(t, status, rec.Code, rec.Body.String())
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	var p apigen.Problem
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
	require.Equal(t, code, p.Code)
	require.Equal(t, status, p.Status)
	require.Equal(t, "about:blank", p.Type)
	require.Equal(t, http.StatusText(status), p.Title)
	require.Equal(t, webtest.ClusterName, p.Cluster)
	require.True(t, webtest.Now.Equal(p.GeneratedAt))
	return p
}
