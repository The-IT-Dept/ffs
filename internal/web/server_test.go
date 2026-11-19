package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
)

func TestServer_DefaultsAndHeaders(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) })
	srv := NewServer(config.Default(), api, nil)
	require.Equal(t, "127.0.0.1:8080", srv.Server.Addr)
	require.Equal(t, 10*time.Second, srv.Server.ReadHeaderTimeout)
	require.False(t, srv.NeedLeaderElection())

	for _, c := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/api/v1/findings", 200},
		{"GET", "/", 404},
		{"POST", "/api/v1/findings", 405},
		{"DELETE", "/", 405},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), c.method, c.path, nil)
		req.Host = "127.0.0.1:8080" // what a port-forward sends
		srv.Server.Handler.ServeHTTP(rec, req)
		require.Equal(t, c.status, rec.Code, c.method+" "+c.path)
		require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		require.Equal(t, "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'",
			rec.Header().Get("Content-Security-Policy"))
	}
}

// TestServer_RejectsForeignHost is the regression test for F11: a DNS-rebinding page reaches the
// port-forwarded server under a name its author controls, so any Host that is not localhost, an
// IP literal or a configured name is refused before the API or dashboard runs.
func TestServer_RejectsForeignHost(t *testing.T) {
	reached := 0
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached++; _, _ = w.Write([]byte(`{"items":[]}`)) })
	dash := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached++; _, _ = w.Write([]byte("<html>")) })
	cfg := config.Default()
	cfg.AllowedHosts = []string{"ffs.example.com"}
	h := NewServer(cfg, api, dash).Server.Handler
	serve := func(host, path string) *httptest.ResponseRecorder {
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
			rec := serve(host, path)
			require.Equal(t, http.StatusMisdirectedRequest, rec.Code, "%s %s", host, path)
			require.NotContains(t, rec.Body.String(), "items")
			require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		}
	}
	require.Zero(t, reached, "no handler runs for a foreign host")

	for _, host := range []string{"localhost:8080", "localhost", "LOCALHOST:8080", "127.0.0.1:8080", "[::1]:8080", "[::1]",
		"10.42.0.17:8080", "ffs.example.com", "FFS.example.com:443", ""} {
		rec := serve(host, "/api/v1/findings")
		require.Equal(t, http.StatusOK, rec.Code, host)
		require.Equal(t, "no-store", rec.Header().Get("Cache-Control"), host)
	}
}
