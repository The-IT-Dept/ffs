// Package apiserver implements the generated strict server of the ffs read-only API
// (api/openapi.yaml) over the store's read model.
package apiserver

import (
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// BaseURL is the path every operation lives under.
const BaseURL = "/api/v1"

// FeedInfo names a registered feed and how long its last success may age before it is stale.
type FeedInfo struct {
	Name       string
	StaleAfter time.Duration
}

// PodCounter reports live pods per owner key; *inventory.Inventory implements it. A nil map means
// the counts are not known yet.
type PodCounter interface{ PodCounts() map[string]int }

// Options are the Server's dependencies.
type Options struct {
	Store  *store.Store
	Config config.Config
	Feeds  []FeedInfo
	EOL    *eol.Evaluator // nil = no lifecycle data
	Kube   client.Reader  // Exception resources; nil = none
	Pods   PodCounter     // nil = pod counts are null
	Now    func() time.Time
	Log    logr.Logger
}

// Server answers the API's operations. It never writes.
type Server struct{ o Options }

var _ apigen.StrictServerInterface = (*Server)(nil)

// New returns a Server over o. A nil Now means time.Now; a zero Log discards.
func New(o Options) *Server {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log.GetSink() == nil {
		o.Log = logr.Discard()
	}
	return &Server{o: o}
}

// Handler returns the HTTP handler of every operation below BaseURL. Parameters the generated
// router cannot bind are a 400 invalid_parameter problem, a handler error is the problem it maps to
// (500 internal when it maps to none), and a path no operation matches is a 404 not_found problem.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.writeProblem(w, r, notFound("no such API path"))
	})
	strict := apigen.NewStrictHandlerWithOptions(s, nil, apigen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  s.paramError,
		ResponseErrorHandlerFunc: s.responseError,
	})
	return apigen.HandlerWithOptions(strict, apigen.StdHTTPServerOptions{
		BaseURL: BaseURL, BaseRouter: mux, ErrorHandlerFunc: s.paramError,
	})
}

// paramError answers a request whose parameters could not be bound.
func (s *Server) paramError(w http.ResponseWriter, r *http.Request, err error) {
	s.writeProblem(w, r, bindProblem(err))
}

// responseError answers a request whose handler failed: with the problem the error maps to, or 500
// internal, logged, with a generic detail.
func (s *Server) responseError(w http.ResponseWriter, r *http.Request, err error) {
	p := problemOf(err)
	if p == nil {
		s.o.Log.Error(err, "API request failed", "path", r.URL.Path)
		p = &Problem{Status: http.StatusInternalServerError, Code: apigen.ProblemCodeInternal, Detail: "internal error"}
	}
	s.writeProblem(w, r, p)
}

func (s *Server) writeProblem(w http.ResponseWriter, r *http.Request, p *Problem) {
	cluster, at := s.stamp()
	writeProblem(w, r, p, cluster, at)
}
