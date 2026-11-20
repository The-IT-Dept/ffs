package ui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func serve(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, target, nil))
	return rec
}

func TestSPA_CachesAndFallback(t *testing.T) {
	dist := fstest.MapFS{"index.html": {Data: []byte(`<div id="root"></div>`)}, "assets/index-abc.js": {Data: []byte("x")},
		"theme.js": {Data: []byte("t")}, ".keep": {}}
	h := Handler(dist)

	rec := serve(t, h, http.MethodGet, "/assets/index-abc.js")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "public, max-age=31536000, immutable", rec.Header().Get("Cache-Control"))
	// The host's MIME database may say text/javascript or application/javascript.
	require.Contains(t, rec.Header().Get("Content-Type"), "javascript")
	require.Equal(t, "x", rec.Body.String())

	rec = serve(t, h, http.MethodGet, "/theme.js")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
	require.Equal(t, "t", rec.Body.String())

	for _, target := range []string{"/", "/index.html", "/workloads/Deployment/shop/web",
		"/images/unknown%3Aghcr.io%2Fexample%2Fprivate%3A1.0", "/assets"} {
		rec := serve(t, h, http.MethodGet, target)
		require.Equal(t, http.StatusOK, rec.Code, target) // never a 301, /index.html included
		require.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"), target)
		require.Equal(t, "no-cache", rec.Header().Get("Cache-Control"), target)
		require.Equal(t, `<div id="root"></div>`, rec.Body.String(), target)
	}

	rec = serve(t, h, http.MethodGet, "/assets/missing.js")
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.NotContains(t, rec.Body.String(), "root")

	rec = serve(t, h, http.MethodHead, "/workloads")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, rec.Body.String())
}

func TestSPA_PlaceholderWhenNotBuilt(t *testing.T) {
	h := Handler(fstest.MapFS{".keep": {}})
	for _, target := range []string{"/", "/coverage"} {
		rec := serve(t, h, http.MethodGet, target)
		require.Equal(t, http.StatusOK, rec.Code, target)
		require.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"), target)
		require.Equal(t, "no-cache", rec.Header().Get("Cache-Control"), target)
		require.Equal(t, NotBuiltPage, rec.Body.String(), target)
	}
	_, err := fs.Stat(Dist(), ".keep")
	require.NoError(t, err) // the embed pattern keeps .keep, so go build works without a UI build
}
