package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/api"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/web/ui"
)

// stub is a handler that records that it ran and writes body.
type stub struct {
	ran  int
	body string
}

func (s *stub) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.ran++
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, s.body)
}

func serve(t *testing.T, h http.Handler, method, target, host string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	req.Host = host
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_HeadersAndCSP(t *testing.T) {
	const want = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	require.Equal(t, want, CSP)

	apiStub := &stub{body: `{"ok":true}`}
	// Over gzhttp's 1 KiB minimum, so only the bypass keeps it uncompressed.
	streamStub := &stub{body: strings.Repeat("data: {}\n\n", 400)}
	dist := fstest.MapFS{"index.html": {Data: []byte(`<div id="root"></div>`)}, "assets/app.js": {Data: []byte("console.log(1)")}}
	cfg := config.Default()
	cfg.ClusterName = "test"
	h := Handler(cfg, Handlers{API: apiStub, Stream: streamStub, UI: ui.Handler(dist)})
	const host = "127.0.0.1:8080"
	gz := map[string]string{"Accept-Encoding": "gzip"}
	security := func(rec *httptest.ResponseRecorder, what string) {
		t.Helper()
		require.Equal(t, want, rec.Header().Get("Content-Security-Policy"), what)
		require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"), what)
		require.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"), what)
	}

	rec := serve(t, h, http.MethodGet, "/", host, nil)
	security(rec, "/")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	require.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))

	rec = serve(t, h, http.MethodGet, "/assets/app.js", host, nil)
	security(rec, "/assets/app.js")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "public, max-age=31536000, immutable", rec.Header().Get("Cache-Control"))

	rec = serve(t, h, http.MethodGet, "/api/v1/feeds", host, nil)
	security(rec, "/api/v1/feeds")
	require.Equal(t, 1, apiStub.ran)
	require.Equal(t, `{"ok":true}`, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	rec = serve(t, h, http.MethodGet, "/api/v1/openapi.yaml", host, nil)
	security(rec, "/api/v1/openapi.yaml")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/yaml", rec.Header().Get("Content-Type"))
	require.True(t, bytes.Equal(api.OpenAPI, rec.Body.Bytes()))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	rec = serve(t, h, http.MethodGet, "/api/v1/openapi.yaml", host, gz)
	security(rec, "/api/v1/openapi.yaml gzip")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	zr, err := gzip.NewReader(rec.Body)
	require.NoError(t, err)
	plain, err := io.ReadAll(zr)
	require.NoError(t, err)
	require.True(t, bytes.Equal(api.OpenAPI, plain))
	require.Equal(t, 1, apiStub.ran, "the document is served by the web handler, not the API")

	rec = serve(t, h, http.MethodGet, "/api/v1/stream", host, gz)
	security(rec, "/api/v1/stream")
	require.Equal(t, 1, streamStub.ran)
	require.Empty(t, rec.Header().Get("Content-Encoding"))
	require.Equal(t, streamStub.body, rec.Body.String())
	require.Equal(t, 1, apiStub.ran)

	noStream := Handler(cfg, Handlers{API: apiStub, UI: ui.Handler(dist)})
	rec = serve(t, noStream, http.MethodGet, "/api/v1/stream", host, nil)
	security(rec, "/api/v1/stream without a stream")
	require.Equal(t, 2, apiStub.ran, "with no stream handler the API answers the stream path")

	rec = serve(t, h, http.MethodPost, "/api/v1/feeds", host, nil)
	security(rec, "POST")
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	require.Equal(t, "GET, HEAD", rec.Header().Get("Allow"))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	rec = serve(t, h, http.MethodGet, "/api/v1/feeds", "rebind.example", nil)
	security(rec, "foreign host")
	require.Equal(t, http.StatusMisdirectedRequest, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.NotContains(t, rec.Body.String(), "test", "the 421 does not name the cluster")
	require.Equal(t, 2, apiStub.ran)
}

// TestServer_RejectsForeignHost is the regression test for F11: a DNS-rebinding page reaches the
// port-forwarded server under a name its author controls, so any Host that is not localhost, an
// IP literal or a configured name is refused before the API or the UI runs.
func TestServer_RejectsForeignHost(t *testing.T) {
	reached := 0
	apiH := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached++; _, _ = w.Write([]byte(`{"items":[]}`)) })
	dash := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached++; _, _ = w.Write([]byte("<html>")) })
	cfg := config.Default()
	cfg.AllowedHosts = []string{"ffs.example.com"}
	h := Handler(cfg, Handlers{API: apiH, UI: dash})
	serveHost := func(host, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, host := range []string{"rebind.example:8080", "rebind.example", "127.0.0.1.nip.io:8080", "localhost.example.com",
		"ffs.example.com.evil.test"} {
		for _, path := range []string{"/api/v1/findings?priority=high", "/api/v1/owners", "/"} {
			rec := serveHost(host, path)
			require.Equal(t, http.StatusMisdirectedRequest, rec.Code, "%s %s", host, path)
			require.NotContains(t, rec.Body.String(), "items")
			require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		}
	}
	require.Zero(t, reached, "no handler runs for a foreign host")

	for _, host := range []string{"localhost:8080", "localhost", "LOCALHOST:8080", "127.0.0.1:8080", "[::1]:8080", "[::1]",
		"10.42.0.17:8080", "ffs.example.com", "FFS.example.com:443", ""} {
		rec := serveHost(host, "/api/v1/findings")
		require.Equal(t, http.StatusOK, rec.Code, host)
		require.Equal(t, "no-store", rec.Header().Get("Cache-Control"), host)
	}
}

func TestServer_DefaultsAndShutdownHook(t *testing.T) {
	called := make(chan struct{})
	srv := NewServer(config.Default(), Handlers{API: http.NotFoundHandler()}, func() { close(called) })
	require.Equal(t, "127.0.0.1:8080", srv.Server.Addr)
	require.Equal(t, 10*time.Second, srv.Server.ReadHeaderTimeout)
	require.Zero(t, srv.Server.WriteTimeout, "the event stream stays open")
	require.False(t, srv.NeedLeaderElection())
	require.Equal(t, "web", srv.Name)

	require.NoError(t, srv.Server.Shutdown(t.Context()))
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("the shutdown hook did not run")
	}
}
