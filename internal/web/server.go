// Package web serves the read-only HTTP API and, when one is supplied, the dashboard.
package web

import (
	"net"
	"net/http"
	"strings"
	"time"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/config"
)

const (
	csp             = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'"
	headerTimeout   = 10 * time.Second
	shutdownTimeout = 5 * time.Second

	misdirected = "This host name is not served. Add it to allowedHosts in the ffs configuration."
)

// NewServer returns the HTTP server runnable: api below /api/v1/, dashboard (when not nil) for
// everything else. Every response carries the security headers and only GET and HEAD are served.
// A request is answered only when its Host is localhost, an IP literal or one of
// cfg.AllowedHosts; any other name gets 421. The server has no authentication, and the documented
// access path is a port-forward to the workstation's loopback, so without this check a
// DNS-rebinding page the operator visits could read the API under its own name.
// The server does not wait for the leader lease, so the read-only API answers while it is pending.
func NewServer(cfg config.Config, api, dashboard http.Handler) *manager.Server {
	if dashboard == nil {
		dashboard = http.NotFoundHandler()
	}
	allowed := make(map[string]bool, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		allowed[normalHost(h)] = true
	}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", api)
	mux.Handle("/", dashboard)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Content-Security-Policy", csp)
		hd.Set("Cache-Control", "no-store")
		if !hostAllowed(r.Host, allowed) {
			http.Error(w, misdirected, http.StatusMisdirectedRequest)
			return
		}
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

// hostAllowed reports whether a request's Host header, with any port, may be answered: localhost,
// any IP literal, or a name in allowed. A rebinding page always uses a name its author controls;
// an IP literal cannot be rebound. An empty Host (HTTP/1.0) never comes from a browser.
func hostAllowed(host string, allowed map[string]bool) bool {
	if host == "" {
		return true
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = normalHost(host)
	return host == "localhost" || net.ParseIP(host) != nil || allowed[host]
}

// normalHost lowercases a host name and drops IPv6 brackets and a trailing dot.
func normalHost(h string) string {
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.TrimSuffix(strings.ToLower(h), ".")
}
