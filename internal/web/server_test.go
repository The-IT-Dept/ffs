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
		srv.Server.Handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), c.method, c.path, nil))
		require.Equal(t, c.status, rec.Code, c.method+" "+c.path)
		require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		require.Equal(t, "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'",
			rec.Header().Get("Content-Security-Policy"))
	}
}
