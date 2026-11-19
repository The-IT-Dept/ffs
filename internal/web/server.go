// Package web serves the read-only HTTP API and, when one is supplied, the dashboard.
package web

import (
	"net/http"
	"time"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/config"
)

const (
	csp             = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'"
	headerTimeout   = 10 * time.Second
	shutdownTimeout = 5 * time.Second
)

// NewServer returns the HTTP server runnable: api below /api/v1/, dashboard (when not nil) for
// everything else. Every response carries the security headers and only GET and HEAD are served.
// The server does not wait for the leader lease, so the read-only API answers while it is pending.
func NewServer(cfg config.Config, api, dashboard http.Handler) *manager.Server {
	if dashboard == nil {
		dashboard = http.NotFoundHandler()
	}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", api)
	mux.Handle("/", dashboard)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Content-Security-Policy", csp)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			hd.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mux.ServeHTTP(w, r)
	})
	return &manager.Server{
		Name:            "web",
		Server:          &http.Server{Addr: cfg.Listen, Handler: h, ReadHeaderTimeout: headerTimeout},
		ShutdownTimeout: ptr.To(shutdownTimeout),
	}
}
