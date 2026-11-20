package agentapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/output/metrics"
)

// fixedAuth authenticates every token as worker-1, or fails with err.
type fixedAuth struct{ err error }

func (f fixedAuth) Authenticate(context.Context, string) (Identity, error) {
	if f.err != nil {
		return Identity{}, f.err
	}
	return Identity{Node: "worker-1", Pod: "ffs-agent-x7k2p", PodUID: "uid-1", ServiceAccount: "ffs-agent", Namespace: "ffs-agent"}, nil
}

type answer struct {
	code   int
	header http.Header
	body   []byte
}

func serve(t *testing.T, h http.Handler, method, path, bearer string, body io.Reader, contentLength int64) answer {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, body)
	req.ContentLength = contentLength
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	b, err := io.ReadAll(w.Body)
	require.NoError(t, err)
	return answer{code: w.Code, header: w.Header(), body: b}
}

// requireError checks a JSON error answer with exactly one key, "error".
func requireError(t *testing.T, a answer, code int, msg string) {
	t.Helper()
	require.Equal(t, code, a.code, string(a.body))
	require.Equal(t, "application/json", a.header.Get("Content-Type"))
	var m map[string]any
	require.NoError(t, json.Unmarshal(a.body, &m), string(a.body))
	require.Len(t, m, 1, string(a.body))
	if msg != "" {
		require.Equal(t, msg, m["error"])
	} else {
		require.Contains(t, m, "error")
	}
}

func TestServer_ReportOverSizeCapRejected(t *testing.T) {
	rec := &reportRecorder{}
	h := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: rec, MaxReportBytes: 1 << 20}).Handler()
	body := `{"node":"worker-1","kind":"full","host":{"syftJSON":"` + strings.Repeat("a", 2<<20) + `"}}`

	a := serve(t, h, http.MethodPost, wire.PathReport, "tok", strings.NewReader(body), int64(len(body)))
	requireError(t, a, http.StatusRequestEntityTooLarge, "report larger than 1048576 bytes")

	a = serve(t, h, http.MethodPost, wire.PathReport, "tok", strings.NewReader(body), -1)
	requireError(t, a, http.StatusRequestEntityTooLarge, "report larger than 1048576 bytes")
	require.Empty(t, rec.calls, "the handler never sees an oversized report")

	sboms := &sbomRecorder{}
	h = NewServer(ServerOptions{Auth: fixedAuth{}, Reports: rec, SBOMs: sboms, MaxSBOMBytes: 1 << 20}).Handler()
	body = `{"node":"worker-1","syftJSON":{"x":"` + strings.Repeat("a", 2<<20) + `"}}`
	a = serve(t, h, http.MethodPost, wire.PathSBOM, "tok", strings.NewReader(body), -1)
	requireError(t, a, http.StatusRequestEntityTooLarge, "SBOM result larger than 1048576 bytes")
	require.Empty(t, sboms.calls)
}

func TestServer_StatusCodesAndErrorBodies(t *testing.T) {
	rec := &reportRecorder{resp: wire.ReportResponse{Applied: true, Config: wire.AgentConfig{JitterPercent: 10}}}
	sboms := &sbomRecorder{}
	cfg := wire.AgentConfig{ReportIntervalSeconds: 21600, ImageListIntervalSeconds: 300, JitterPercent: 10, MaxReportBytes: 33554432}
	opts := ServerOptions{Auth: fixedAuth{}, Reports: rec, SBOMs: sboms, Config: func() wire.AgentConfig { return cfg }, MaxReportBytes: 1 << 20}
	h := NewServer(opts).Handler()
	report := func() io.Reader { return strings.NewReader(`{"node":"worker-1","kind":"images"}`) }

	a := serve(t, h, http.MethodPost, wire.PathReport, "", report(), -1)
	requireError(t, a, http.StatusUnauthorized, "unauthenticated")
	require.Equal(t, "Bearer", a.header.Get("WWW-Authenticate"))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, wire.PathReport, report())
	req.Header.Set("Authorization", "Basic dXNlcjpwdw==")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code, "a non-bearer scheme is unauthenticated")

	hu := NewServer(ServerOptions{Auth: fixedAuth{err: fmt.Errorf("%w: expired", ErrUnauthenticated)}, Reports: rec}).Handler()
	requireError(t, serve(t, hu, http.MethodPost, wire.PathReport, "x", report(), -1), http.StatusUnauthorized, "unauthenticated")
	hd := NewServer(ServerOptions{Auth: fixedAuth{err: errors.New("apiserver down")}, Reports: rec}).Handler()
	requireError(t, serve(t, hd, http.MethodPost, wire.PathReport, "x", report(), -1), http.StatusInternalServerError, "internal error")

	a = serve(t, h, http.MethodPost, wire.PathReport, "tok", strings.NewReader(`{"node":`), -1)
	requireError(t, a, http.StatusBadRequest, "")
	require.Contains(t, string(a.body), "request body is not valid JSON: ")

	for _, tc := range []struct {
		err  error
		code int
		msg  string
	}{
		{fmt.Errorf("%w: node worker-1 is not in the cluster", ErrForbidden), http.StatusForbidden, "node worker-1 is not in the cluster"},
		{fmt.Errorf("%w: unknown report kind \"partial\"", ErrBadRequest), http.StatusBadRequest, `unknown report kind "partial"`},
		{errors.New("disk I/O"), http.StatusInternalServerError, "internal error"},
	} {
		rec.err = tc.err
		requireError(t, serve(t, h, http.MethodPost, wire.PathReport, "tok", report(), -1), tc.code, tc.msg)
	}
	rec.err = nil
	a = serve(t, h, http.MethodPost, wire.PathReport, "tok", report(), -1)
	require.Equal(t, http.StatusOK, a.code)
	require.Equal(t, "application/json", a.header.Get("Content-Type"))
	var resp wire.ReportResponse
	require.NoError(t, json.Unmarshal(a.body, &resp))
	require.Equal(t, rec.resp, resp)

	a = serve(t, h, http.MethodPost, wire.PathSBOM, "tok", strings.NewReader(`{"id":"w1","node":"worker-2"}`), -1)
	requireError(t, a, http.StatusForbidden, "token is for node worker-1, not worker-2")
	require.Empty(t, sboms.calls)
	a = serve(t, h, http.MethodPost, wire.PathSBOM, "tok", strings.NewReader(`{"id":"w1","node":"worker-1","digest":"sha256:aa"}`), -1)
	require.Equal(t, http.StatusNoContent, a.code)
	require.Empty(t, a.body)
	require.Equal(t, []wire.SBOMResult{{ID: "w1", Node: "worker-1", Digest: "sha256:aa"}}, sboms.calls)

	a = serve(t, h, http.MethodGet, wire.PathConfig, "tok", nil, 0)
	require.Equal(t, http.StatusOK, a.code)
	var got wire.AgentConfig
	require.NoError(t, json.Unmarshal(a.body, &got))
	require.Equal(t, cfg, got)
	requireError(t, serve(t, h, http.MethodGet, wire.PathConfig, "", nil, 0), http.StatusUnauthorized, "unauthenticated")

	a = serve(t, h, http.MethodGet, wire.PathReport, "tok", nil, 0)
	requireError(t, a, http.StatusMethodNotAllowed, "method not allowed")
	require.Equal(t, "POST", a.header.Get("Allow"))
	requireError(t, serve(t, h, http.MethodGet, "/agent/v1/nope", "tok", nil, 0), http.StatusNotFound, "not found")

	require.True(t, NewServer(opts).NeedLeaderElection())
}

func TestServer_StartServesTLS13AndStops(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir, 7)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	rec := &reportRecorder{resp: wire.ReportResponse{Applied: true}}
	srv := NewServer(ServerOptions{Listen: addr, CertDir: dir, Auth: fixedAuth{}, Reports: rec})
	require.ErrorContains(t, srv.Start(context.Background()), "agent API: ", "Start listens on Listen, which is taken")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.serve(ctx, ln) }() // the listener is handed over: no port to lose between two listens

	pemBytes, err := os.ReadFile(filepath.Join(dir, "tls.crt")) //nolint:gosec // G304: the test's own file
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pemBytes))
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	var (
		status  int
		version uint16
		serial  *big.Int
	)
	require.Eventually(t, func() bool {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+addr+wire.PathReport,
			bytes.NewReader([]byte(`{"node":"worker-1","kind":"images"}`)))
		req.Header.Set("Authorization", "Bearer tok")
		resp, err := hc.Do(req)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		status, version, serial = resp.StatusCode, resp.TLS.Version, resp.TLS.PeerCertificates[0].SerialNumber
		return true
	}, 5*time.Second, 20*time.Millisecond)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, uint16(tls.VersionTLS13), version)
	require.Equal(t, big.NewInt(7), serial)
	hc.CloseIdleConnections()

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return")
	}
}

func TestCertReloader_ReloadsChangedFilesAtMostEvery30s(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	serialOf := func(r *certReloader) int64 {
		t.Helper()
		c, err := r.GetCertificate(nil)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		require.NoError(t, err)
		return leaf.SerialNumber.Int64()
	}
	writeCert(t, dir, 1)
	r := newCertReloader(dir, clk.Now)
	require.Equal(t, int64(1), serialOf(r))

	writeCert(t, dir, 2)
	clk.Add(10 * time.Second)
	require.Equal(t, int64(1), serialOf(r), "files are checked at most every 30s")
	clk.Add(21 * time.Second)
	require.Equal(t, int64(2), serialOf(r))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), []byte("corrupt"), 0o600))
	clk.Add(31 * time.Second)
	require.Equal(t, int64(2), serialOf(r), "a pair that fails to load keeps the last good one")

	empty := t.TempDir()
	r = newCertReloader(empty, clk.Now)
	_, err := r.GetCertificate(nil)
	require.Error(t, err, "no pair was ever loaded")
	writeCert(t, empty, 3)
	clk.Add(31 * time.Second)
	require.Equal(t, int64(3), serialOf(r))
}

func TestWireConfig_FromNodeAgentConfig(t *testing.T) {
	require.Equal(t, wire.AgentConfig{ReportIntervalSeconds: 21600, ImageListIntervalSeconds: 300, JitterPercent: 10,
		MaxImageBytes: 0, MaxReportBytes: 33554432}, WireConfig(config.Default().NodeAgent))
}

func TestServer_CountsRejectedReports(t *testing.T) {
	rejected := func(reason string) float64 {
		return testutil.ToFloat64(metrics.AgentReports.WithLabelValues(metrics.AgentReportRejected, reason))
	}
	rec := &reportRecorder{resp: wire.ReportResponse{Applied: true}}
	sboms := &sbomRecorder{}
	h := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: rec, SBOMs: sboms, MaxReportBytes: 1 << 20, MaxSBOMBytes: 1 << 20}).Handler()
	report := func(node string) io.Reader { return strings.NewReader(`{"node":"` + node + `","kind":"images"}`) }
	result := func(node string) io.Reader {
		return strings.NewReader(`{"id":"w1","node":"` + node + `","digest":"sha256:aa"}`)
	}
	big := `{"node":"worker-1","kind":"full","host":{"syftJSON":"` + strings.Repeat("a", 2<<20) + `"}}`

	for _, tc := range []struct {
		name, path, bearer string
		body               io.Reader
		length             int64
		err                error
		code               int
		reason             string
	}{
		{"no token", wire.PathReport, "", report("worker-1"), -1, nil, http.StatusUnauthorized, metrics.AgentRejectUnauthenticated},
		{"another node", wire.PathReport, "tok", report("worker-2"), -1, nil, http.StatusForbidden, metrics.AgentRejectForbidden},
		{"over the size cap", wire.PathReport, "tok", strings.NewReader(big), int64(len(big)), nil, http.StatusRequestEntityTooLarge,
			metrics.AgentRejectTooLarge},
		{"invalid JSON", wire.PathReport, "tok", strings.NewReader(`{"node":`), -1, nil, http.StatusBadRequest, metrics.AgentRejectBadRequest},
		{"refused by the handler", wire.PathReport, "tok", report("worker-1"), -1, fmt.Errorf("%w: unknown report kind", ErrBadRequest),
			http.StatusBadRequest, metrics.AgentRejectBadRequest},
		{"SBOM, no token", wire.PathSBOM, "", result("worker-1"), -1, nil, http.StatusUnauthorized, metrics.AgentRejectUnauthenticated},
		{"SBOM, another node", wire.PathSBOM, "tok", result("worker-2"), -1, nil, http.StatusForbidden, metrics.AgentRejectForbidden},
		{"SBOM, not offered", wire.PathSBOM, "tok", result("worker-1"), -1, fmt.Errorf("%w: sha256:aa was not offered", ErrForbidden),
			http.StatusForbidden, metrics.AgentRejectForbidden},
		{"SBOM, over the size cap", wire.PathSBOM, "tok", strings.NewReader(big), int64(len(big)), nil, http.StatusRequestEntityTooLarge,
			metrics.AgentRejectTooLarge},
	} {
		before := rejected(tc.reason)
		rec.err, sboms.err = tc.err, tc.err
		a := serve(t, h, http.MethodPost, tc.path, tc.bearer, tc.body, tc.length)
		require.Equal(t, tc.code, a.code, tc.name)
		require.Equal(t, before+1, rejected(tc.reason), tc.name)
	}

	sum := func() float64 {
		total := 0.0
		for _, r := range metrics.AgentRejectReasons {
			total += rejected(r)
		}
		return total
	}
	before := sum()
	rec.err, sboms.err = errors.New("disk I/O"), nil
	require.Equal(t, http.StatusInternalServerError, serve(t, h, http.MethodPost, wire.PathReport, "tok", report("worker-1"), -1).code)
	rec.err = nil
	require.Equal(t, http.StatusOK, serve(t, h, http.MethodPost, wire.PathReport, "tok", report("worker-1"), -1).code)
	require.Equal(t, http.StatusNoContent, serve(t, h, http.MethodPost, wire.PathSBOM, "tok", result("worker-1"), -1).code)
	require.Equal(t, before, sum(), "neither a 500 nor a success is a rejection")
}

// blockingReports is a ReportHandler that holds every report until release is closed, counting the reports
// it holds.
type blockingReports struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingReports) Report(ctx context.Context, _ Identity, _ *wire.Report) (wire.ReportResponse, error) {
	b.entered <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return wire.ReportResponse{Applied: true}, nil
}

// inFlight is the ffs_agent_ingest_bytes_in_flight gauge.
func inFlight() float64 { return testutil.ToFloat64(metrics.AgentIngestBytesInFlight) }

// TestServer_IngestBudgetDefersFullReports: full reports beyond the ingest budget wait IngestWait and are
// answered 429 with a Retry-After of 10 to 60 seconds, before their bodies are read; the bytes in flight
// never exceed the budget, and a deferred report is counted as deferred, not rejected.
func TestServer_IngestBudgetDefersFullReports(t *testing.T) {
	const size = 1 << 20
	prefix, suffix := `{"node":"worker-1","kind":"full","agentVersion":"`, `"}`
	body := prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix
	require.Len(t, body, size)
	reports := &blockingReports{entered: make(chan struct{}, 8), release: make(chan struct{})}
	srv := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: reports, MaxReportBytes: 4 * size, IngestBudget: 3 * size,
		IngestWait: 50 * time.Millisecond})
	h := srv.Handler()
	deferred := func() float64 {
		return testutil.ToFloat64(metrics.AgentReports.WithLabelValues(metrics.AgentReportDeferred, ""))
	}
	deferredBefore, held := deferred(), inFlight()
	// post sends one full report and returns its status; it runs on other goroutines, so it asserts nothing.
	post := func() int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, wire.PathReport, strings.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	answers := make(chan int, 8)
	for range 3 {
		go func() { answers <- post() }()
	}
	for range 3 {
		<-reports.entered // three reports hold the whole budget
	}
	require.Equal(t, held+3*size, inFlight())

	for range 4 {
		a := serve(t, h, http.MethodPost, wire.PathReport, "tok", strings.NewReader(body), int64(len(body)))
		requireError(t, a, http.StatusTooManyRequests, "the controller is busy; retry later")
		secs, err := strconv.Atoi(a.header.Get("Retry-After"))
		require.NoError(t, err)
		require.GreaterOrEqual(t, secs, 10)
		require.LessOrEqual(t, secs, 60)
	}
	// A body without a Content-Length takes MaxReportBytes, capped at the budget: it waits too.
	a := serve(t, h, http.MethodPost, wire.PathReport, "tok", strings.NewReader(body), -1)
	require.Equal(t, http.StatusTooManyRequests, a.code)
	require.Equal(t, deferredBefore+5, deferred())
	require.Equal(t, held+3*size, inFlight(), "a deferred report takes none of the budget")

	close(reports.release)
	for range 3 {
		require.Equal(t, http.StatusOK, <-answers)
	}
	require.Equal(t, held, inFlight(), "every share is released")

	// With the budget free, a report goes through at once.
	go func() { answers <- post() }()
	<-reports.entered
	require.Equal(t, http.StatusOK, <-answers)
	require.Equal(t, held, inFlight())
}

// blockingSBOMs is an SBOMHandler that holds every result until release is closed. With wait set it is also
// a ResultWindow whose results may wait that long, recording the requests asked about and those left unread,
// as "<node>/<request ID>".
type blockingSBOMs struct {
	entered chan struct{}
	release chan struct{}

	mu     sync.Mutex
	wait   time.Duration
	asked  []string
	unread []string
}

func (b *blockingSBOMs) SBOM(ctx context.Context, _ Identity, _ *wire.SBOMResult) error {
	b.entered <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return nil
}

func (b *blockingSBOMs) setWait(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.wait = d
}

func (b *blockingSBOMs) askedFor() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.asked)
}

func (b *blockingSBOMs) unreadRequests() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.unread)
}

// windowedSBOMs is blockingSBOMs as a ResultWindow.
type windowedSBOMs struct{ *blockingSBOMs }

func (w windowedSBOMs) ResultWait(node, id string) (time.Duration, func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.asked = append(w.asked, node+"/"+id)
	return w.wait, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.unread = append(w.unread, node+"/"+id)
	}
}

// sizedBody is a JSON body of exactly size bytes: prefix, padding and suffix.
func sizedBody(t *testing.T, prefix, suffix string, size int) string {
	t.Helper()
	body := prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix
	require.Len(t, body, size)
	return body
}

// resultRequest is a POST of an SBOM result body naming the request workID ("": none).
func resultRequest(ctx context.Context, body, workID string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, wire.PathSBOM, strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Authorization", "Bearer tok")
	if workID != "" {
		req.Header.Set(wire.HeaderWorkID, workID)
	}
	return req
}

// postResult sends an SBOM result naming workID and returns the answer.
func postResult(t *testing.T, h http.Handler, body, workID string) answer {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, resultRequest(context.Background(), body, workID))
	return answer{code: w.Code, header: w.Header(), body: w.Body.Bytes()}
}

// postAsync sends an SBOM result naming workID on another goroutine and returns its status on the channel; it
// asserts nothing.
func postAsync(ctx context.Context, h http.Handler, body, workID string) <-chan int {
	answer := make(chan int, 1)
	go func() {
		req := resultRequest(ctx, body, workID)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		answer <- w.Code
	}()
	return answer
}

// TestServer_ReportsDoNotWaitBehindSBOMResults: SBOM results have a budget of their own, so a result holding
// all of it, and another waiting for it, never defer a report.
func TestServer_ReportsDoNotWaitBehindSBOMResults(t *testing.T) {
	const size = 1 << 20
	sboms := &blockingSBOMs{entered: make(chan struct{}, 4), release: make(chan struct{})}
	rec := &reportRecorder{resp: wire.ReportResponse{Applied: true}}
	srv := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: rec, SBOMs: sboms, MaxReportBytes: 2 * size, MaxSBOMBytes: 2 * size,
		IngestBudget: size, SBOMBudget: size, IngestWait: 50 * time.Millisecond})
	h := srv.Handler()
	held := inFlight()
	result := sizedBody(t, `{"id":"w1","node":"worker-1","digest":"sha256:aa","failure":"`, `"}`, size)
	first := postAsync(context.Background(), h, result, "w1")
	<-sboms.entered // the first result holds the whole SBOM budget
	waiting := postAsync(context.Background(), h, result, "w1")

	report := sizedBody(t, `{"node":"worker-1","kind":"images","agentVersion":"`, `"}`, size)
	for range 3 {
		a := serve(t, h, http.MethodPost, wire.PathReport, "tok", strings.NewReader(report), int64(len(report)))
		require.Equal(t, http.StatusOK, a.code, "a report of the whole report budget goes through: %s", a.body)
	}
	require.Len(t, rec.calls, 3)
	require.Equal(t, held+size, inFlight(), "only the first result's share is held")

	close(sboms.release)
	require.Equal(t, http.StatusNoContent, <-first)
	require.Equal(t, http.StatusNoContent, <-waiting, "the waiting result has its turn")
	require.Equal(t, held, inFlight())
}

// TestServer_SBOMWaitEndsWithItsRequest: a result waits for the SBOM budget no longer than the request it
// names (wire.HeaderWorkID) takes a result (ResultWindow). It is then answered 503 and that request is marked
// answered; a result whose request takes none is answered 403 before its body is read.
func TestServer_SBOMWaitEndsWithItsRequest(t *testing.T) {
	const size = 1 << 20
	forbidden := func() float64 {
		return testutil.ToFloat64(metrics.AgentReports.WithLabelValues(metrics.AgentReportRejected, metrics.AgentRejectForbidden))
	}
	sboms := &blockingSBOMs{entered: make(chan struct{}, 4), release: make(chan struct{})}
	h := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: &reportRecorder{}, SBOMs: windowedSBOMs{sboms},
		MaxSBOMBytes: 2 * size, SBOMBudget: size}).Handler()
	held := inFlight()
	result := sizedBody(t, `{"id":"w1","node":"worker-1","digest":"sha256:aa","failure":"`, `"}`, size)

	before := forbidden()
	requireError(t, postResult(t, h, result, "w1"), http.StatusForbidden, "no request to worker-1 takes this result")
	require.Equal(t, before+1, forbidden())
	require.Empty(t, sboms.entered, "the handler never sees it")
	require.Equal(t, []string{"worker-1/w1"}, sboms.askedFor(), "the window of the request the result names")

	sboms.setWait(time.Hour)
	first := postAsync(context.Background(), h, result, "w1")
	<-sboms.entered // the first result holds the whole SBOM budget

	sboms.setWait(50 * time.Millisecond)
	start := time.Now()
	a := postResult(t, h, result, "w2")
	requireError(t, a, http.StatusServiceUnavailable, "the controller could not read the result in time")
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
	require.Equal(t, []string{"worker-1/w2"}, sboms.unreadRequests(), "the request it names is answered, and no other")
	require.Equal(t, held+size, inFlight())

	close(sboms.release)
	require.Equal(t, http.StatusNoContent, <-first)
	require.Equal(t, held, inFlight())
}

// TestServer_DefaultBudgets: reports and SBOM results have 192 and 64 MiB, 256 MiB in all, and the configuration
// refuses a report larger than the report budget, so a report's share of it is always its whole size.
func TestServer_DefaultBudgets(t *testing.T) {
	srv := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: &reportRecorder{}})
	require.Equal(t, int64(192<<20), srv.o.IngestBudget)
	require.Equal(t, int64(64<<20), srv.o.SBOMBudget)
	require.Equal(t, int64(config.NodeAgentReportBudget), srv.o.IngestBudget)
	c := config.Default()
	c.NodeAgent.MaxReportBytes = srv.o.IngestBudget
	require.NoError(t, c.Validate())
	c.NodeAgent.MaxReportBytes++
	require.ErrorContains(t, c.Validate(), "nodeAgent.maxReportBytes")
}

// TestServer_SBOMWaitStaysBelowTheAgentTimeout: however long its request takes a result, a result waits for
// the SBOM budget at most a minute less than the agent's client timeout, so the agent sees the 503 and can
// send it again; a result that waited that long leaves its request unread.
func TestServer_SBOMWaitStaysBelowTheAgentTimeout(t *testing.T) {
	const size = 1 << 20
	sboms := &blockingSBOMs{entered: make(chan struct{}, 4), release: make(chan struct{})}
	opts := ServerOptions{Auth: fixedAuth{}, Reports: &reportRecorder{}, SBOMs: windowedSBOMs{sboms}, MaxSBOMBytes: 2 * size,
		SBOMBudget: size}
	require.Equal(t, wire.ClientTimeout-time.Minute, NewServer(opts).o.MaxResultWait, "by default")
	opts.MaxResultWait = time.Hour
	require.Equal(t, wire.ClientTimeout-time.Minute, NewServer(opts).o.MaxResultWait, "never longer")
	require.Less(t, wire.ClientTimeout, writeTimeout, "the agent's timeout ends before the server's")

	opts.MaxResultWait = 50 * time.Millisecond
	h := NewServer(opts).Handler()
	result := sizedBody(t, `{"id":"w1","node":"worker-1","digest":"sha256:aa","failure":"`, `"}`, size)
	sboms.setWait(time.Hour) // the requests take a result for an hour
	first := postAsync(context.Background(), h, result, "w1")
	<-sboms.entered

	start := time.Now()
	requireError(t, postResult(t, h, result, "w2"), http.StatusServiceUnavailable, "the controller could not read the result in time")
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
	require.Less(t, time.Since(start), 10*time.Second, "not the request's hour")
	require.Equal(t, []string{"worker-1/w2"}, sboms.unreadRequests())

	close(sboms.release)
	require.Equal(t, http.StatusNoContent, <-first)
}

// TestServer_AbandonedSBOMResultIsUnread: a result whose HTTP request ends while it waits for the SBOM budget
// (the agent gave up, or stopped) was never read, so its request is not counted against the image.
func TestServer_AbandonedSBOMResultIsUnread(t *testing.T) {
	const size = 1 << 20
	sboms := &blockingSBOMs{entered: make(chan struct{}, 4), release: make(chan struct{}), wait: time.Hour}
	h := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: &reportRecorder{}, SBOMs: windowedSBOMs{sboms},
		MaxSBOMBytes: 2 * size, SBOMBudget: size}).Handler()
	held := inFlight()
	result := sizedBody(t, `{"id":"w1","node":"worker-1","digest":"sha256:aa","failure":"`, `"}`, size)
	first := postAsync(context.Background(), h, result, "w1")
	<-sboms.entered

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	abandoned := postAsync(ctx, h, result, "w2")
	require.Eventually(t, func() bool { return slices.Contains(sboms.askedFor(), "worker-1/w2") }, 10*time.Second, time.Millisecond)
	cancel()
	<-abandoned
	require.Equal(t, []string{"worker-1/w2"}, sboms.unreadRequests(), "the abandoned result's request is answered")
	require.Equal(t, held+size, inFlight(), "it took none of the budget")

	close(sboms.release)
	require.Equal(t, http.StatusNoContent, <-first)
	require.Equal(t, held, inFlight())
}

// serveTLS serves s on a free local port with a certificate of its own until the test ends, and returns its URL
// and a client built like the agent's (a clone of the default transport): over HTTP/2 when h2, else HTTP/1.1
// only. The listener is handed to the server, so no other process can take the port between two listens.
func serveTLS(t *testing.T, s *Server, h2 bool) (string, *http.Client) {
	t.Helper()
	s.o.CertDir = t.TempDir()
	writeCert(t, s.o.CertDir, 1)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	pemBytes, err := os.ReadFile(filepath.Join(s.o.CertDir, "tls.crt"))
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pemBytes))
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	if !h2 {
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP1(true)
	}
	hc := &http.Client{Transport: tr}
	t.Cleanup(hc.CloseIdleConnections)
	return "https://" + ln.Addr().String(), hc
}

// sent is the answer to sendResult: the protocol and status, or the error.
type sent struct {
	proto  string
	status int
	err    error
}

// sendResult POSTs an SBOM result body naming workID to url on another goroutine, and returns the answer on
// the channel; it asserts nothing.
func sendResult(hc *http.Client, url string, body io.Reader, workID string) <-chan sent {
	return sendResultWith(context.Background(), hc, url, body, -1, workID)
}

// sendResultWith is sendResult with the request's context and Content-Length (-1: the client's choice).
func sendResultWith(ctx context.Context, hc *http.Client, url string, body io.Reader, contentLength int64, workID string) <-chan sent {
	out := make(chan sent, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+wire.PathSBOM, body)
		if err != nil {
			out <- sent{err: err}
			return
		}
		if contentLength >= 0 {
			req.ContentLength = contentLength
		}
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set(wire.HeaderWorkID, workID)
		resp, err := hc.Do(req)
		if err != nil {
			out <- sent{err: err}
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		out <- sent{proto: resp.Proto, status: resp.StatusCode}
	}()
	return out
}

// TestServer_SBOMBodyReadAfterALongWait: a result that waited for the SBOM budget longer than readTimeout is
// still read in full once it has its share, over the TLS server Start runs, with HTTP/2 (which agents use)
// and with HTTP/1.1. The body is several times an HTTP/2 stream's receive window, so most of it is read after
// the wait.
func TestServer_SBOMBodyReadAfterALongWait(t *testing.T) {
	for _, proto := range []string{"HTTP/2.0", "HTTP/1.1"} {
		t.Run(proto, func(t *testing.T) {
			const size = 4 << 20
			sboms := &blockingSBOMs{entered: make(chan struct{}, 4), release: make(chan struct{}), wait: time.Hour}
			s := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: &reportRecorder{}, SBOMs: windowedSBOMs{sboms},
				MaxSBOMBytes: 2 * size, SBOMBudget: size})
			s.readTimeout = 2 * time.Second // ample for the body, even with the race detector
			url, hc := serveTLS(t, s, proto == "HTTP/2.0")
			result := sizedBody(t, `{"id":"w1","node":"worker-1","digest":"sha256:aa","failure":"`, `"}`, size)

			first := sendResult(hc, url, strings.NewReader(result), "w1")
			select { // the first result holds the whole SBOM budget
			case <-sboms.entered:
			case got := <-first:
				t.Fatalf("the first result was answered without being handled: %+v", got)
			}
			second := sendResult(hc, url, strings.NewReader(result), "w2")
			require.Eventually(t, func() bool { return slices.Contains(sboms.askedFor(), "worker-1/w2") }, 10*time.Second,
				time.Millisecond)
			time.Sleep(s.readTimeout + 500*time.Millisecond) // the second waits past the read timeout
			close(sboms.release)
			require.Equal(t, sent{proto: proto, status: http.StatusNoContent}, <-first)
			require.Equal(t, sent{proto: proto, status: http.StatusNoContent}, <-second, "its body is read after the wait")
			require.Empty(t, sboms.unreadRequests())
		})
	}
	require.Zero(t, NewServer(ServerOptions{}).httpServer(context.Background(), nil).ReadTimeout,
		"over HTTP/2 a server ReadTimeout cuts a body off once it has passed, whatever deadline the handler sets")
}

// TestServer_StalledBodyIsCutOff: with no server ReadTimeout, the handlers' read deadline still ends a body that
// stops arriving, over HTTP/2 and HTTP/1.1, and nothing of it is handled.
func TestServer_StalledBodyIsCutOff(t *testing.T) {
	for _, proto := range []string{"HTTP/2.0", "HTTP/1.1"} {
		t.Run(proto, func(t *testing.T) {
			sboms := &blockingSBOMs{entered: make(chan struct{}, 4), release: make(chan struct{}), wait: time.Hour}
			s := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: &reportRecorder{}, SBOMs: windowedSBOMs{sboms}})
			s.readTimeout = 200 * time.Millisecond
			url, hc := serveTLS(t, s, proto == "HTTP/2.0")
			body, stall := io.Pipe()
			defer func() { _ = stall.Close() }()
			go func() { _, _ = stall.Write([]byte(`{"id":"w1","node":"worker-1",`)) }() // then nothing more

			select {
			case got := <-sendResult(hc, url, body, "w1"):
				if got.err == nil { // or the server closed the connection under the body
					require.Equal(t, http.StatusBadRequest, got.status)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the stalled body was not cut off")
			}
			require.Empty(t, sboms.entered, "nothing was handled")
		})
	}
}

// TestServer_UnreadableResultAfterAWaitIsUnread: a result whose body cannot be read in full once it has its share
// of the SBOM budget leaves its request unread, so it is not counted against the image, over HTTP/2 and
// HTTP/1.1. After a wait close to MaxResultWait the agent's client timeout leaves about a minute for the body;
// here the agent gives up after sending a quarter of it.
func TestServer_UnreadableResultAfterAWaitIsUnread(t *testing.T) {
	for _, proto := range []string{"HTTP/2.0", "HTTP/1.1"} {
		t.Run(proto, func(t *testing.T) {
			const size = 1 << 20
			sboms := &blockingSBOMs{entered: make(chan struct{}, 4), release: make(chan struct{}), wait: time.Hour}
			s := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: &reportRecorder{}, SBOMs: windowedSBOMs{sboms},
				MaxSBOMBytes: 2 * size, SBOMBudget: size})
			url, hc := serveTLS(t, s, proto == "HTTP/2.0")
			held := inFlight()
			result := sizedBody(t, `{"id":"w1","node":"worker-1","digest":"sha256:aa","failure":"`, `"}`, size)
			first := sendResult(hc, url, strings.NewReader(result), "w1")
			select { // the first result holds the whole SBOM budget
			case <-sboms.entered:
			case got := <-first:
				t.Fatalf("the first result was answered without being handled: %+v", got)
			}

			// The second result is half the size, so its share tells it apart from the first's.
			body, stall := io.Pipe()
			defer func() { _ = stall.Close() }()
			go func() { _, _ = stall.Write([]byte(result[:size/4])) }() // then nothing more
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			second := sendResultWith(ctx, hc, url, body, size/2, "w2")
			require.Eventually(t, func() bool { return slices.Contains(sboms.askedFor(), "worker-1/w2") }, 10*time.Second,
				time.Millisecond)
			close(sboms.release)
			require.Equal(t, sent{proto: proto, status: http.StatusNoContent}, <-first)
			require.Eventually(t, func() bool { return inFlight() == held+size/2 }, 10*time.Second, time.Millisecond,
				"the second result has its share and reads its body")
			require.Empty(t, sboms.unreadRequests())

			cancel() // the agent's client timeout
			// Over HTTP/1.1 the client's write of the body ends only when its body does; the agent's is a file.
			_ = stall.CloseWithError(context.Canceled)
			require.Error(t, (<-second).err)
			require.Eventually(t, func() bool { return len(sboms.unreadRequests()) > 0 }, 10*time.Second, time.Millisecond)
			require.Equal(t, []string{"worker-1/w2"}, sboms.unreadRequests(), "the request it answers is not counted")
			require.Eventually(t, func() bool { return inFlight() == held }, 10*time.Second, time.Millisecond)
			require.Empty(t, sboms.entered, "nothing of it was handled")
		})
	}
}

// slowHandlers hold every report and SBOM result for hold before answering, unless the request's context ends
// first, which they answer with its error.
type slowHandlers struct{ hold time.Duration }

func (s slowHandlers) wait(ctx context.Context) error {
	select {
	case <-time.After(s.hold):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s slowHandlers) Report(ctx context.Context, _ Identity, _ *wire.Report) (wire.ReportResponse, error) {
	return wire.ReportResponse{Applied: true}, s.wait(ctx)
}

func (s slowHandlers) SBOM(ctx context.Context, _ Identity, _ *wire.SBOMResult) error {
	return s.wait(ctx)
}

// TestServer_HandlingOutlastsTheReadTimeout: once a report's or a result's body is read, handling it may take
// longer than the read timeout, over HTTP/2 and HTTP/1.1. Over HTTP/1.1 the server watches the connection with
// a background read once the body is read, and a read deadline still in force would end that read and cancel
// the request's context.
func TestServer_HandlingOutlastsTheReadTimeout(t *testing.T) {
	for _, proto := range []string{"HTTP/2.0", "HTTP/1.1"} {
		t.Run(proto, func(t *testing.T) {
			slow := slowHandlers{hold: time.Second}
			s := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: slow, SBOMs: slow})
			s.readTimeout = 200 * time.Millisecond
			url, hc := serveTLS(t, s, proto == "HTTP/2.0")

			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+wire.PathReport,
				strings.NewReader(`{"node":"worker-1","kind":"images"}`))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer tok")
			resp, err := hc.Do(req)
			require.NoError(t, err)
			b, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusOK, resp.StatusCode, "the report is handled: %s", b)
			require.Equal(t, proto, resp.Proto)

			got := <-sendResult(hc, url, strings.NewReader(`{"id":"w1","node":"worker-1","digest":"sha256:aa","failure":"boom"}`), "w1")
			require.Equal(t, sent{proto: proto, status: http.StatusNoContent}, got, "the result is handled")
		})
	}
}
