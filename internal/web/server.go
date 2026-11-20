// Package web serves the web UI and the read-only HTTP API.
package web

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/klauspost/compress/gzhttp"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/api"
	"github.com/the-it-dept/ffs/internal/config"
)

// CSP is the Content-Security-Policy of every response. The UI loads only its own scripts, styles,
// images and connections. Inline styles are allowed because the dialog scroll lock injects a style
// element; inline scripts are not.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const (
	headerTimeout   = 10 * time.Second
	shutdownTimeout = 5 * time.Second

	streamPath  = "/api/v1/stream"
	openAPIPath = "/api/v1/openapi.yaml"

	misdirected = "This host name is not served. Add it to allowedHosts in the ffs configuration."
)

// Handlers are what the server routes to: API below /api/v1/, Stream at /api/v1/stream and UI for
// every other path. A nil Stream routes the stream path to API; a nil UI answers 404.
type Handlers struct{ API, Stream, UI http.Handler }

// Handler applies the guards and routes to h. Every response carries the security headers. A
// request is answered only when its Host is localhost, an IP literal or one of cfg.AllowedHosts; any
// other name gets 421. The server has no authentication, and the documented access path is a
// port-forward to the workstation's loopback, so without this check a DNS-rebinding page the
// operator visits could read the API under its own name. Only GET and HEAD are served. API
// responses are never cached. Everything except the event stream is compressed.
func Handler(cfg config.Config, h Handlers) http.Handler {
	allowed := make(map[string]bool, len(cfg.AllowedHosts))
	for _, name := range cfg.AllowedHosts {
		allowed[normalHost(name)] = true
	}
	apiH, stream, ui := h.API, h.Stream, h.UI
	if apiH == nil {
		apiH = http.NotFoundHandler()
	}
	if stream == nil {
		stream = apiH
	}
	if ui == nil {
		ui = http.NotFoundHandler()
	}
	mux := http.NewServeMux()
	mux.HandleFunc(openAPIPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(api.OpenAPI)
	})
	mux.Handle("/api/", apiH)
	mux.Handle("/", ui)
	compressed := gzhttp.GzipHandler(mux)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Content-Security-Policy", CSP)
		hd.Set("Referrer-Policy", "no-referrer")
		if !hostAllowed(r.Host, allowed) {
			hd.Set("Cache-Control", "no-store")
			http.Error(w, misdirected, http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			hd.Set("Cache-Control", "no-store")
			hd.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hd.Set("Cache-Control", "no-store")
		}
		if r.URL.Path == streamPath {
			stream.ServeHTTP(w, r)
			return
		}
		compressed.ServeHTTP(w, r)
	})
}

// NewServer returns the HTTP server runnable over Handler(cfg, h). onShutdown, when not nil, runs
// when the server shuts down, so long-lived responses such as the event stream can end. There is no
// write timeout, because the event stream stays open. The server does not wait for the leader
// lease, so the read-only API answers while it is pending.
func NewServer(cfg config.Config, h Handlers, onShutdown func()) *manager.Server {
	srv := &http.Server{Addr: cfg.Listen, Handler: Handler(cfg, h), ReadHeaderTimeout: headerTimeout}
	if onShutdown != nil {
		srv.RegisterOnShutdown(onShutdown)
	}
	return &manager.Server{Name: "web", Server: srv, ShutdownTimeout: ptr.To(shutdownTimeout)}
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
