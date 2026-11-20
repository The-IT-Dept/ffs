package agentapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/semaphore"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/sbom"
)

const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 5 * time.Minute
	// writeTimeout is longer than the agent's client timeout, so the agent sees the answer.
	writeTimeout    = wire.ClientTimeout + time.Minute
	idleTimeout     = 2 * time.Minute
	maxHeaderBytes  = 16 << 10
	shutdownTimeout = 5 * time.Second
	// certCheckEvery is how often the certificate files are checked for changes.
	certCheckEvery = 30 * time.Second
	// jitterPercent spreads every agent's intervals.
	jitterPercent = 10

	// defaultIngestBudget caps the bytes of report bodies being read and handled at once, the host part's
	// preparation included: a rollout's herd of full reports waits or is deferred instead of taking the
	// controller past its memory limit. SBOM results have a budget of their own (ServerOptions.SBOMBudget),
	// so a large result waiting for its share never holds up reports, nor reports results. The config refuses
	// a nodeAgent.maxReportBytes above it, so a report's share is always its size.
	defaultIngestBudget = config.NodeAgentReportBudget
	// defaultSBOMBudget caps the bytes of SBOM result bodies being read and handled at once. A body's share
	// is capped at the budget, so a result of the largest size takes all of it.
	defaultSBOMBudget = 64 << 20
	// defaultIngestWait is how long a report waits for its share of the budget before it is answered
	// 429 with a Retry-After of retryAfterMin to retryAfterMax seconds.
	defaultIngestWait = 2 * time.Second
	retryAfterMin     = 10
	retryAfterMax     = 60
	// maxResultWait is the longest an SBOM result waits for its share of the SBOM budget: a minute short of
	// the agent's client timeout, so the agent sees the answer and can send the result again.
	maxResultWait = wire.ClientTimeout - time.Minute
)

var (
	// ErrForbidden is a request the agent may not make. A handler error wrapping it, fmt.Errorf("%w: <text>"),
	// is answered 403 {"error":"<text>"}.
	ErrForbidden = errors.New("agentapi: forbidden")
	// ErrBadRequest is a request the controller cannot use; it is answered 400 like ErrForbidden.
	ErrBadRequest = errors.New("agentapi: bad request")
)

// ReportHandler handles an authenticated report whose node matches the token's.
type ReportHandler interface {
	Report(ctx context.Context, id Identity, r *wire.Report) (wire.ReportResponse, error)
}

// SBOMHandler handles an authenticated SBOM result whose node matches the token's.
type SBOMHandler interface {
	SBOM(ctx context.Context, id Identity, res *wire.SBOMResult) error
}

// ServerOptions configures the agent API server.
type ServerOptions struct {
	Listen, CertDir string
	MaxReportBytes  int64 // 0: 32 MiB
	MaxSBOMBytes    int64 // 0: sbom.MaxSBOMBytes + 1 MiB
	Auth            Authenticator
	Reports         ReportHandler           // required
	SBOMs           SBOMHandler             // nil: /agent/v1/sbom is not served
	Config          func() wire.AgentConfig // nil: /agent/v1/config is not served
	Log             logr.Logger
	Now             func() time.Time // certificate reload and rate-limit clock; nil: time.Now
	IngestBudget    int64            // bytes of report bodies read and handled at once; 0: 192 MiB
	SBOMBudget      int64            // bytes of SBOM result bodies read and handled at once; 0: 64 MiB
	IngestWait      time.Duration    // a report's wait for budget before 429; 0: 2s
	MaxResultWait   time.Duration    // an SBOM result's longest wait for budget before 503; 0, or more than 9m: 9m
}

// ResultWindow is implemented by an SBOMHandler that knows how long a node's result may still be accepted
// (*WorkQueue does). The server then bounds a result's wait for the SBOM budget by it.
type ResultWindow interface {
	// ResultWait is how long a result from node answering the request id (wire.HeaderWorkID; "" when the
	// agent sent none) may wait before it is read, zero or less when that request takes no result, and
	// unread, which the server calls when the result was not read: it waited too long, or its HTTP request
	// ended while it waited.
	ResultWait(node, id string) (wait time.Duration, unread func())
}

// Server serves /agent/v1 over TLS on the leader.
type Server struct {
	o       ServerOptions
	fails   *failLimiter        // failed authentications per source IP
	reports *semaphore.Weighted // the report budget, by body bytes
	sboms   *semaphore.Weighted // the SBOM result budget, by body bytes
}

// NewServer returns the agent API server.
func NewServer(o ServerOptions) *Server {
	if o.MaxReportBytes <= 0 {
		o.MaxReportBytes = 32 << 20
	}
	if o.MaxSBOMBytes <= 0 {
		o.MaxSBOMBytes = sbom.MaxSBOMBytes + 1<<20
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.IngestBudget <= 0 {
		o.IngestBudget = defaultIngestBudget
	}
	if o.SBOMBudget <= 0 {
		o.SBOMBudget = defaultSBOMBudget
	}
	if o.IngestWait <= 0 {
		o.IngestWait = defaultIngestWait
	}
	if o.MaxResultWait <= 0 || o.MaxResultWait > maxResultWait {
		o.MaxResultWait = maxResultWait
	}
	return &Server{o: o, fails: newFailLimiter(), reports: semaphore.NewWeighted(o.IngestBudget),
		sboms: semaphore.NewWeighted(o.SBOMBudget)}
}

// acquire takes n bytes of budget, waiting at most wait (no limit when 0) and while ctx lasts. It returns the
// release func, or false when the budget could not be had. The bytes held count in AgentIngestBytesInFlight.
func acquire(ctx context.Context, budget *semaphore.Weighted, n int64, wait time.Duration) (func(), bool) {
	if wait > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, wait)
		defer cancel()
	}
	if err := budget.Acquire(ctx, n); err != nil {
		return nil, false
	}
	metrics.AgentIngestBytesInFlight.Add(float64(n))
	return func() {
		metrics.AgentIngestBytesInFlight.Sub(float64(n))
		budget.Release(n)
	}, true
}

// bodyWeight is the budget a request body takes: its Content-Length, or limit when it has none, never more
// than limit nor than the whole budget, and at least 1.
func bodyWeight(r *http.Request, limit, budget int64) int64 {
	n := r.ContentLength
	if n < 0 || n > limit {
		n = limit
	}
	return min(max(n, 1), budget)
}

// retryAfter is a Retry-After in seconds, spread between retryAfterMin and retryAfterMax so deferred agents
// do not come back together.
func retryAfter() int { return retryAfterMin + rand.IntN(retryAfterMax-retryAfterMin+1) } //nolint:gosec // jitter, not a secret

// NeedLeaderElection makes the agent API leader-only: reports write the leader's store.
func (s *Server) NeedLeaderElection() bool { return true }

// WireConfig is the agent config the controller hands out.
func WireConfig(c config.NodeAgentConfig) wire.AgentConfig {
	return wire.AgentConfig{
		ReportIntervalSeconds:    int64(c.ReportInterval / time.Second),
		ImageListIntervalSeconds: int64(c.ImageListInterval / time.Second),
		JitterPercent:            jitterPercent,
		MaxReportBytes:           c.MaxReportBytes,
	}
}

// Start serves until ctx ends. It listens even before a certificate exists: handshakes fail until the files
// appear, and changed files are picked up within 30s.
func (s *Server) Start(ctx context.Context) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.o.Listen)
	if err != nil {
		return fmt.Errorf("agent API: %w", err)
	}
	reloader := newCertReloader(s.o.CertDir, s.o.Now)
	reloader.log = s.o.Log
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: reloader.GetCertificate},
		ErrorLog:          log.New(logWriter{s.o.Log}, "", 0),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	s.o.Log.Info("agent API listening", "address", ln.Addr().String())
	err = srv.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		<-stopped
		return nil
	}
	return err
}

// logWriter sends the HTTP server's own messages (TLS handshake errors) to the debug log.
type logWriter struct{ log logr.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.log.V(1).Info(strings.TrimSpace(string(p)))
	return len(p), nil
}

// Handler returns the routes, with JSON 404 and 405 answers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.PathReport, s.serveReport)
	if s.o.SBOMs != nil {
		mux.HandleFunc("POST "+wire.PathSBOM, s.serveSBOM)
	}
	if s.o.Config != nil {
		mux.HandleFunc("GET "+wire.PathConfig, s.serveConfig)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, pattern := mux.Handler(r)
		if pattern != "" {
			h.ServeHTTP(w, r)
			return
		}
		// The mux's own 404 and 405 answers are text/plain; answer them as JSON, keeping Allow.
		rec := &statusRecorder{header: http.Header{}}
		h.ServeHTTP(rec, r)
		if allow := rec.header.Get("Allow"); allow != "" {
			w.Header().Set("Allow", allow)
		}
		switch rec.status {
		case http.StatusMethodNotAllowed:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	})
}

// statusWriter records the status a handler answers with, and whether a 429 deferred the request for the
// ingest budget rather than rejecting it.
type statusWriter struct {
	http.ResponseWriter
	status   int
	deferred bool
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController and decode reach the server's own writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// statusRecorder captures the status and headers of the mux's error answers.
type statusRecorder struct {
	header http.Header
	status int
}

func (r *statusRecorder) Header() http.Header { return r.header }
func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(p), nil
}
func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// authenticate checks the bearer token, answering the request itself when it fails. A source IP whose
// failed authentications exceed its token bucket gets 429, and its tokens are not reviewed until it refills.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	ip, now := sourceIP(r), s.o.Now()
	if s.fails.limited(ip, now) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "too many failed authentications")
		return Identity{}, false
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		s.fails.fail(ip, now)
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return Identity{}, false
	}
	id, err := s.o.Auth.Authenticate(r.Context(), strings.TrimSpace(token))
	switch {
	case errors.Is(err, ErrUnauthenticated):
		s.fails.fail(ip, now)
		s.o.Log.V(1).Info("agent token rejected", "reason", err.Error(), "remote", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return Identity{}, false
	case err != nil:
		s.o.Log.Error(err, "authenticating an agent", "remote", r.RemoteAddr)
		writeError(w, http.StatusInternalServerError, "internal error")
		return Identity{}, false
	}
	return id, true
}

// declaredTooLarge answers 413 for a request whose Content-Length is over max, before any of the body is read
// or any ingest budget is taken.
func declaredTooLarge(w http.ResponseWriter, r *http.Request, max int64, what string) bool {
	if r.ContentLength <= max {
		return false
	}
	writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("%s larger than %d bytes", what, max))
	return true
}

// decode reads one JSON value of at most max bytes, answering the request itself when it fails.
func decode(w http.ResponseWriter, r *http.Request, max int64, what string, v any) bool {
	tooLarge := fmt.Sprintf("%s larger than %d bytes", what, max)
	if declaredTooLarge(w, r, max, what) {
		return false
	}
	// MaxBytesReader tells the server's own writer to close the connection once the limit is hit.
	limited := w
	if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); ok {
		limited = u.Unwrap()
	}
	if err := json.NewDecoder(http.MaxBytesReader(limited, r.Body, max)).Decode(v); err != nil {
		if mbe := new(http.MaxBytesError); errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, tooLarge)
			return false
		}
		writeError(w, http.StatusBadRequest, "request body is not valid JSON: "+err.Error())
		return false
	}
	return true
}

// handlerError answers a handler's error: ErrForbidden 403 and ErrBadRequest 400 with their text, else 500.
func (s *Server) handlerError(w http.ResponseWriter, id Identity, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, errorText(err, ErrForbidden))
	case errors.Is(err, ErrBadRequest):
		writeError(w, http.StatusBadRequest, errorText(err, ErrBadRequest))
	default:
		s.o.Log.Error(err, "handling an agent request", "node", id.Node)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// errorText is the text a handler put after the sentinel: fmt.Errorf("%w: <text>", sentinel) gives "<text>".
func errorText(err, sentinel error) string {
	msg := err.Error()
	prefix := sentinel.Error() + ": "
	if i := strings.Index(msg, prefix); i >= 0 {
		return msg[i+len(prefix):]
	}
	return strings.TrimPrefix(msg, "agentapi: ")
}

func nodeMismatch(w http.ResponseWriter, id Identity, node string) bool {
	if node == id.Node {
		return false
	}
	writeError(w, http.StatusForbidden, fmt.Sprintf("token is for node %s, not %s", id.Node, node))
	return true
}

// countAnswer counts a report or SBOM result answered with w's status: a 4xx is rejected, by reason, or
// deferred for the ingest budget. Applied and duplicate reports are counted by the handler.
func countAnswer(w *statusWriter) {
	switch {
	case w.deferred:
		metrics.AgentReports.WithLabelValues(metrics.AgentReportDeferred, "").Inc()
	case w.status >= 400 && w.status < 500:
		metrics.AgentReports.WithLabelValues(metrics.AgentReportRejected, rejectReason(w.status)).Inc()
	}
}

// rejectReason is the AgentReports reason of a 4xx status.
func rejectReason(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return metrics.AgentRejectUnauthenticated
	case http.StatusTooManyRequests:
		return metrics.AgentRejectRateLimited
	case http.StatusForbidden:
		return metrics.AgentRejectForbidden
	case http.StatusRequestEntityTooLarge:
		return metrics.AgentRejectTooLarge
	}
	return metrics.AgentRejectBadRequest
}

// serveReport takes the report's share of the ingest budget before reading its body, and keeps it until
// the report is handled (its host part prepared and stored). A report that cannot have it within
// IngestWait is answered 429 with a jittered Retry-After; the agent resends it without cataloguing again.
func (s *Server) serveReport(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw}
	defer countAnswer(w)
	id, ok := s.authenticate(w, r)
	if !ok || declaredTooLarge(w, r, s.o.MaxReportBytes, "report") {
		return
	}
	release, ok := acquire(r.Context(), s.reports, bodyWeight(r, s.o.MaxReportBytes, s.o.IngestBudget), s.o.IngestWait)
	if !ok {
		if r.Context().Err() == nil {
			w.deferred = true
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter()))
			writeError(w, http.StatusTooManyRequests, "the controller is busy; retry later")
		}
		return
	}
	defer release()
	var rep wire.Report
	if !decode(w, r, s.o.MaxReportBytes, "report", &rep) || nodeMismatch(w, id, rep.Node) {
		return
	}
	resp, err := s.o.Reports.Report(r.Context(), id, &rep)
	if err != nil {
		s.handlerError(w, id, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// serveSBOM takes the result's share of the SBOM budget before reading its body. The agent has no
// back-pressure for results, so it waits for as long as the result could still be accepted: until the request
// it answers stops taking a result (ResultWindow), and at most MaxResultWait, which keeps the answer within
// the agent's client timeout. A node whose request takes no result is answered 403 at once. A result that
// waited that long is answered 503, which the agent answers by sending it again while its request takes one.
// A result that was not read, because it waited that long or because its HTTP request ended while it waited,
// leaves its request uncounted against the image: the controller held it up.
func (s *Server) serveSBOM(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw}
	defer countAnswer(w)
	id, ok := s.authenticate(w, r)
	if !ok || declaredTooLarge(w, r, s.o.MaxSBOMBytes, "SBOM result") {
		return
	}
	wait, unread := s.o.MaxResultWait, func() {}
	if window, bounded := s.o.SBOMs.(ResultWindow); bounded {
		var until time.Duration
		if until, unread = window.ResultWait(id.Node, r.Header.Get(wire.HeaderWorkID)); until <= 0 {
			writeError(w, http.StatusForbidden, "no request to "+id.Node+" takes this result")
			return
		}
		wait = min(wait, until)
	}
	release, ok := acquire(r.Context(), s.sboms, bodyWeight(r, s.o.MaxSBOMBytes, s.o.SBOMBudget), wait)
	if !ok {
		unread()
		if r.Context().Err() == nil {
			s.o.Log.Info("an SBOM result waited too long for the ingest budget; the agent sends it again while its "+
				"request takes one", "node", id.Node, "waited", wait)
			writeError(w, http.StatusServiceUnavailable, "the controller could not read the result in time")
		}
		return // or the agent went away
	}
	defer release()
	// The server's read timeout runs from the start of the request: the wait must not use up the body's time.
	_ = http.NewResponseController(rw).SetReadDeadline(time.Now().Add(readTimeout))
	var res wire.SBOMResult
	if !decode(w, r, s.o.MaxSBOMBytes, "SBOM result", &res) || nodeMismatch(w, id, res.Node) {
		return
	}
	if err := s.o.SBOMs.SBOM(r.Context(), id, &res); err != nil {
		s.handlerError(w, id, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) serveConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticate(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.o.Config())
}

// certReloader serves the certificate in dir (tls.crt, tls.key), re-reading the files when they change,
// checked at most every certCheckEvery. A pair that fails to load keeps the last good one.
type certReloader struct {
	dir string
	now func() time.Time
	log logr.Logger

	mu       sync.Mutex
	cert     *tls.Certificate
	checked  time.Time
	crt, key fileStamp
}

type fileStamp struct {
	mtime time.Time
	size  int64
}

func (f fileStamp) same(o fileStamp) bool { return f.mtime.Equal(o.mtime) && f.size == o.size }

func newCertReloader(dir string, now func() time.Time) *certReloader {
	return &certReloader{dir: dir, now: now, log: logr.Discard()}
}

func stamp(p string) (fileStamp, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{mtime: fi.ModTime(), size: fi.Size()}, nil
}

// GetCertificate is the TLS server's certificate callback.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.cert != nil && now.Sub(r.checked) < certCheckEvery {
		return r.cert, nil
	}
	r.checked = now
	crtPath, keyPath := filepath.Join(r.dir, "tls.crt"), filepath.Join(r.dir, "tls.key")
	crt, err := stamp(crtPath)
	var key fileStamp
	if err == nil {
		key, err = stamp(keyPath)
	}
	if err == nil && r.cert != nil && crt.same(r.crt) && key.same(r.key) {
		return r.cert, nil
	}
	if err == nil {
		var c tls.Certificate
		if c, err = tls.LoadX509KeyPair(crtPath, keyPath); err == nil {
			r.cert, r.crt, r.key = &c, crt, key
			r.log.Info("agent API certificate loaded", "dir", r.dir)
			return r.cert, nil
		}
	}
	if r.cert != nil {
		r.log.Error(err, "reloading the agent API certificate; keeping the previous one", "dir", r.dir)
		return r.cert, nil
	}
	return nil, fmt.Errorf("agent API certificate: %w", err)
}
