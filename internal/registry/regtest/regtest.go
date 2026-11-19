// Package regtest runs an in-memory OCI registry for tests. Pushes go straight into the registry
// in-process, so they bypass basic auth and middleware and are not counted; every request a client
// sends over the network is.
package regtest

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Server is a running test registry.
type Server struct {
	Host string // 127.0.0.1:port

	inner http.Handler

	mu   sync.Mutex
	reqs []seen
}

type seen struct{ method, path string }

// Option configures Start.
type Option func(*config)

type config struct {
	referrers  bool
	user, pass string
	middleware []func(http.Handler) http.Handler
}

// WithReferrers enables the OCI referrers API.
func WithReferrers() Option { return func(c *config) { c.referrers = true } }

// WithBasicAuth requires these credentials on every request, the /v2/ ping included.
func WithBasicAuth(user, pass string) Option {
	return func(c *config) { c.user, c.pass = user, pass }
}

// WithMiddleware wraps the registry (outside basic auth). The first option given is outermost.
func WithMiddleware(m func(http.Handler) http.Handler) Option {
	return func(c *config) { c.middleware = append(c.middleware, m) }
}

// Start runs a registry until the test ends.
func Start(t testing.TB, opts ...Option) *Server {
	t.Helper()
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	s := &Server{inner: ggcrregistry.New(
		ggcrregistry.Logger(log.New(io.Discard, "", 0)),
		ggcrregistry.WithReferrersSupport(cfg.referrers),
	)}
	h := s.inner
	if cfg.user != "" || cfg.pass != "" {
		h = basicAuth(h, cfg.user, cfg.pass)
	}
	for i := len(cfg.middleware) - 1; i >= 0; i-- {
		h = cfg.middleware[i](h)
	}
	srv := httptest.NewServer(s.record(h))
	t.Cleanup(srv.Close)
	s.Host = strings.TrimPrefix(srv.URL, "http://")
	return s
}

func (s *Server) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, seen{r.Method, r.URL.Path})
		s.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func basicAuth(next http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="regtest"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Count returns how many requests with method ("" for any) and a path matching path the registry has
// received over the network.
func (s *Server) Count(method string, path *regexp.Regexp) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.reqs {
		if (method == "" || r.method == method) && path.MatchString(r.path) {
			n++
		}
	}
	return n
}

// Push writes img at ref, "repo:tag" (Host is prefixed); a ref with no tag pushes by digest. It
// returns the image's digest.
func (s *Server) Push(t testing.TB, ref string, img v1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("regtest: digest: %v", err)
	}
	if err := remote.Write(s.ref(t, ref, d), img, remote.WithTransport(handlerTransport{s.inner})); err != nil {
		t.Fatalf("regtest: push %s: %v", ref, err)
	}
	return d.String()
}

// PushIndex writes idx at ref like Push and returns the index digest.
func (s *Server) PushIndex(t testing.TB, ref string, idx v1.ImageIndex) string {
	t.Helper()
	d, err := idx.Digest()
	if err != nil {
		t.Fatalf("regtest: digest: %v", err)
	}
	if err := remote.WriteIndex(s.ref(t, ref, d), idx, remote.WithTransport(handlerTransport{s.inner})); err != nil {
		t.Fatalf("regtest: push %s: %v", ref, err)
	}
	return d.String()
}

func (s *Server) ref(t testing.TB, ref string, d v1.Hash) name.Reference {
	t.Helper()
	ref = strings.TrimPrefix(ref, s.Host+"/")
	full := s.Host + "/" + ref
	if i := strings.LastIndex(ref, "/"); !strings.ContainsAny(ref[i+1:], ":@") {
		full += "@" + d.String()
	}
	r, err := name.ParseReference(full)
	if err != nil {
		t.Fatalf("regtest: reference %q: %v", full, err)
	}
	return r
}

// handlerTransport serves requests in-process from the registry handler.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body == nil {
		req.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// PlatformIndex builds an OCI index with one random image per platform ("linux/amd64",
// "linux/arm64/v8") and the given index annotations. The images are keyed by the platform strings.
func PlatformIndex(t testing.TB, annotations map[string]string, platforms ...string) (v1.ImageIndex, map[string]v1.Image) {
	t.Helper()
	imgs := make(map[string]v1.Image, len(platforms))
	adds := make([]mutate.IndexAddendum, 0, len(platforms))
	for _, ps := range platforms {
		p, err := v1.ParsePlatform(ps)
		if err != nil {
			t.Fatalf("regtest: platform %q: %v", ps, err)
		}
		img, err := random.Image(256, 1)
		if err != nil {
			t.Fatalf("regtest: random image: %v", err)
		}
		cf, err := img.ConfigFile()
		if err != nil {
			t.Fatalf("regtest: config: %v", err)
		}
		cf = cf.DeepCopy()
		cf.OS, cf.Architecture, cf.Variant = p.OS, p.Architecture, p.Variant
		if img, err = mutate.ConfigFile(img, cf); err != nil {
			t.Fatalf("regtest: config: %v", err)
		}
		imgs[ps] = img
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: p}})
	}
	idx := mutate.AppendManifests(mutate.IndexMediaType(empty.Index, types.OCIImageIndex), adds...)
	if len(annotations) > 0 {
		idx = mutate.Annotations(idx, annotations).(v1.ImageIndex)
	}
	return idx, imgs
}
