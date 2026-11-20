package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// recorder records the owner keys the control reports as recomputed.
type recorder struct {
	mu   sync.Mutex
	keys [][]string
}

func (r *recorder) OwnersRecomputed(_ context.Context, keys []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, slices.Clone(keys))
}

// reply is a control server's answer, read in full.
type reply struct {
	status int
	header http.Header
	body   []byte
}

// do sends a request without a body to the control server and reads the answer.
func do(t *testing.T, method, url string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, res.Body.Close()) }()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return reply{status: res.StatusCode, header: res.Header, body: body}
}

// postTransition posts /transition, requires 201 with a JSON body, and decodes it.
func postTransition(t *testing.T, base string) transitionResult {
	t.Helper()
	res := do(t, http.MethodPost, base+"/transition")
	require.Equal(t, http.StatusCreated, res.status, string(res.body))
	require.Equal(t, "application/json", res.header.Get("Content-Type"))
	var got transitionResult
	require.NoError(t, json.Unmarshal(res.body, &got))
	return got
}

func TestControl_TransitionAddsUrgentFindingAndNotifies(t *testing.T) {
	f := webtest.Open(t)
	rec := &recorder{}
	srv := httptest.NewServer(newControl(f.Store, f.Config.ClusterName, rec))
	t.Cleanup(srv.Close)
	before, err := f.Store.OwnerStatsOf(t.Context(), []string{"Deployment/shop/web"})
	require.NoError(t, err)

	got := postTransition(t, srv.URL)
	require.Equal(t, "CVE-2099-0001", got.Advisory)
	require.Equal(t, "Deployment/shop/web", got.Owner)

	fs, err := f.Store.FindingsForOwner(t.Context(), "Deployment/shop/web")
	require.NoError(t, err)
	i := slices.IndexFunc(fs, func(x model.Finding) bool { return x.AdvisoryID == "CVE-2099-0001" })
	require.GreaterOrEqual(t, i, 0)
	require.Equal(t, model.PriorityUrgent, fs[i].Priority)
	require.Equal(t, model.StateOpen, fs[i].State)
	require.Equal(t, model.FindingFingerprint("test", fs[i].Owner, fs[i].ImageRepo, "CVE-2099-0001"), fs[i].Fingerprint)
	require.Equal(t, got.Fingerprint, fs[i].Fingerprint)

	after, err := f.Store.OwnerStatsOf(t.Context(), []string{"Deployment/shop/web"})
	require.NoError(t, err)
	require.Equal(t, before["Deployment/shop/web"].Counts.Urgent+1, after["Deployment/shop/web"].Counts.Urgent) // rollup triggers fired

	ts, err := f.Store.TransitionsAfter(t.Context(), 0, 0)
	require.NoError(t, err)
	last := ts[len(ts)-1]
	require.Equal(t, "CVE-2099-0001", last.AdvisoryID)
	require.Equal(t, model.StateOpen, last.ToState)
	require.Equal(t, model.PriorityUrgent, last.ToPriority)
	require.Equal(t, model.TriggerNewAdvisory, last.Trigger)
	rec.mu.Lock()
	require.Equal(t, [][]string{{"Deployment/shop/web"}}, rec.keys)
	rec.mu.Unlock()

	require.Equal(t, "CVE-2099-0002", postTransition(t, srv.URL).Advisory)

	res := do(t, http.MethodGet, srv.URL+"/transition")
	require.Equal(t, http.StatusMethodNotAllowed, res.status)
	require.Equal(t, "POST", res.header.Get("Allow"))
	require.Equal(t, http.StatusNotFound, do(t, http.MethodPost, srv.URL+"/other").status)
}

func TestControl_NoTemplateIsNotFound(t *testing.T) {
	f := webtest.Open(t)
	webtest.ExecSQL(t, f.Store, `DELETE FROM findings WHERE owner_key = ?`, seededOwner)
	rec := &recorder{}
	srv := httptest.NewServer(newControl(f.Store, f.Config.ClusterName, rec))
	t.Cleanup(srv.Close)

	res := do(t, http.MethodPost, srv.URL+"/transition")
	require.Equal(t, http.StatusNotFound, res.status)
	require.Contains(t, string(res.body), "Deployment/shop/web has no findings in this fixture")
	require.Empty(t, rec.keys)
}

func TestHandlers_ServeAPIAndUI(t *testing.T) {
	f := webtest.Open(t)
	h := web.Handler(f.Config, handlers(f, newHub(f, logr.Discard())))
	for _, tc := range []struct{ path, ctype string }{
		{"/api/v1/feeds", "application/json"}, {"/", "text/html"}, {"/workloads/Deployment/shop/web", "text/html"},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil)
		req.Host = "127.0.0.1:8099" // httptest's default host example.com would get 421
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, tc.path)
		require.True(t, strings.HasPrefix(rr.Header().Get("Content-Type"), tc.ctype), tc.path)
	}
}

func TestOpenFixture_RejectsUnknownKind(t *testing.T) {
	_, err := openFixture(t.Context(), "large", t.TempDir())
	require.ErrorContains(t, err, "small or scale")
}

// TestRun_ControlListenerFailureStopsTheWebServerFirst: when the control address is taken, run returns the
// control listener's error only once the web server has shut down, and then removes the store. The web
// server logs through the logger run was given.
func TestRun_ControlListenerFailureStopsTheWebServerFirst(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // run's store directory
	var lc net.ListenConfig
	taken, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = taken.Close() })
	free, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := free.Addr().String()
	require.NoError(t, free.Close())

	var (
		mu    sync.Mutex
		lines []string
	)
	log := funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, prefix+" "+args)
	}, funcr.Options{})

	err = run(t.Context(), options{Addr: addr, Control: taken.Addr().String(), Fixture: "small"}, log)
	require.ErrorContains(t, err, "control listener: listen tcp "+taken.Addr().String())

	conn, dialErr := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", addr)
	if dialErr == nil {
		require.NoError(t, conn.Close())
	}
	require.Error(t, dialErr, "the web server stopped before run returned")
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	require.Empty(t, entries, "the store directory is removed")

	mu.Lock()
	defer mu.Unlock()
	logged := strings.Join(lines, "\n")
	require.Contains(t, logged, `"msg"="starting server" "name"="web"`)
	require.Contains(t, logged, `"msg"="shutting down server" "name"="web"`)
}
