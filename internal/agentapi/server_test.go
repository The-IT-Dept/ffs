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
	"strings"
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
	require.NoError(t, ln.Close())

	rec := &reportRecorder{resp: wire.ReportResponse{Applied: true}}
	srv := NewServer(ServerOptions{Listen: addr, CertDir: dir, Auth: fixedAuth{}, Reports: rec})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

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
	rejected := func() float64 {
		return testutil.ToFloat64(metrics.AgentReports.WithLabelValues(metrics.AgentReportRejected))
	}
	rec := &reportRecorder{resp: wire.ReportResponse{Applied: true}}
	h := NewServer(ServerOptions{Auth: fixedAuth{}, Reports: rec, MaxReportBytes: 1 << 20}).Handler()
	report := func(node string) io.Reader { return strings.NewReader(`{"node":"` + node + `","kind":"images"}`) }
	big := `{"node":"worker-1","kind":"full","host":{"syftJSON":"` + strings.Repeat("a", 2<<20) + `"}}`

	for _, tc := range []struct {
		name   string
		bearer string
		body   io.Reader
		length int64
		err    error
		code   int
	}{
		{"no token", "", report("worker-1"), -1, nil, http.StatusUnauthorized},
		{"another node", "tok", report("worker-2"), -1, nil, http.StatusForbidden},
		{"over the size cap", "tok", strings.NewReader(big), int64(len(big)), nil, http.StatusRequestEntityTooLarge},
		{"invalid JSON", "tok", strings.NewReader(`{"node":`), -1, nil, http.StatusBadRequest},
		{"refused by the handler", "tok", report("worker-1"), -1, fmt.Errorf("%w: unknown report kind", ErrBadRequest), http.StatusBadRequest},
	} {
		before := rejected()
		rec.err = tc.err
		a := serve(t, h, http.MethodPost, wire.PathReport, tc.bearer, tc.body, tc.length)
		require.Equal(t, tc.code, a.code, tc.name)
		require.Equal(t, before+1, rejected(), tc.name)
	}

	before := rejected()
	rec.err = errors.New("disk I/O")
	require.Equal(t, http.StatusInternalServerError, serve(t, h, http.MethodPost, wire.PathReport, "tok", report("worker-1"), -1).code)
	rec.err = nil
	require.Equal(t, http.StatusOK, serve(t, h, http.MethodPost, wire.PathReport, "tok", report("worker-1"), -1).code)
	require.Equal(t, before, rejected(), "neither a 500 nor a 200 is a rejection")
}
