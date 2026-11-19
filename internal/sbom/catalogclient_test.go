package sbom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

// countingRegistry records Reserve calls on top of a real registry client.
type countingRegistry struct {
	*registry.Client
	reserves atomic.Int32
	lastN    atomic.Int32
}

func (c *countingRegistry) Reserve(rctx context.Context, repo string, n int) error {
	c.reserves.Add(1)
	c.lastN.Store(int32(n))
	return c.Client.Reserve(rctx, repo, n)
}

// fakeCatalog is a cataloguer stand-in on a unix socket that answers every request with status
// and body, or hangs up after reading the request.
type fakeCatalog struct {
	socket string

	mu       sync.Mutex
	status   int
	body     any
	hangup   bool
	got      []CatalogRequest
	reserved []int32 // reserves seen by the time each request arrived
	reg      *countingRegistry
}

func startFakeCatalog(t *testing.T, reg *countingRegistry) *fakeCatalog {
	t.Helper()
	dir, err := os.MkdirTemp("", "ffs") // short path: macOS caps unix socket paths at 104 bytes
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &fakeCatalog{socket: filepath.Join(dir, "c.sock"), reg: reg}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", f.socket)
	require.NoError(t, err)
	srv := &http.Server{Handler: http.HandlerFunc(f.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *fakeCatalog) set(status int, body any, hangup bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body, f.hangup = status, body, hangup
}

func (f *fakeCatalog) serve(w http.ResponseWriter, r *http.Request) {
	var req CatalogRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	f.got = append(f.got, req)
	f.reserved = append(f.reserved, f.reg.reserves.Load())
	status, body, hangup := f.status, f.body, f.hangup
	f.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusTeapot)
		return
	}
	if hangup {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func TestCatalogSource_MapsErrors(t *testing.T) {
	const (
		repo   = "docker.io/library/nginx"
		digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	reg := &countingRegistry{Client: registry.New(registry.Options{Config: config.RegistryConfig{
		Mirrors: map[string]string{"docker.io": "mirror.example.com/hub"},
	}})}
	fake := startFakeCatalog(t, reg)
	cfg := config.Default().Catalog
	cfg.Socket = fake.socket
	src := NewCatalogSource(reg.Client, cfg)
	src.reg = reg
	require.Equal(t, "registry", src.Name())

	req := Request{Repo: repo, Digest: digest, Platform: "linux/amd64", Creds: registry.CredSet{Namespace: "app"}}

	// 200
	cov := model.Coverage{UnattributedELF: 2, Notes: []string{"2 executables not attributed to any package"}}
	fake.set(http.StatusOK, CatalogResponse{SyftJSON: json.RawMessage(`{"artifacts":[]}`), Coverage: cov}, false)
	res, err := src.Acquire(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "registry", res.Source)
	require.NotEmpty(t, res.SyftJSON)
	require.Equal(t, cov, res.Coverage)

	fake.mu.Lock()
	got := fake.got[0]
	reservedAtSend := fake.reserved[0]
	fake.mu.Unlock()
	require.Equal(t, reg.PullRepo(repo)+"@"+digest, got.Ref)
	require.Equal(t, "mirror.example.com/hub/library/nginx@"+digest, got.Ref)
	require.Equal(t, "linux/amd64", got.Platform)
	require.Equal(t, int64(10<<30), got.MaxBytes)
	require.Equal(t, 600, got.TimeoutSeconds)
	require.Equal(t, CatalogAuth{}, got.Auth)
	require.Equal(t, int32(1), reservedAtSend, "Reserve before sending")
	require.Equal(t, int32(2), reg.lastN.Load())

	errBody := func(kind, msg string) CatalogError { return CatalogError{Kind: kind, Error: msg} }
	for _, tc := range []struct {
		name   string
		status int
		body   any
		hangup bool
		socket string
		kind   FailureKind
		reason string // "" skips the check
	}{
		{name: "401", status: 401, body: errBody(KindUnauthorized, "denied"), kind: FailUnresolvable,
			reason: fmt.Sprintf(registry.ReasonUnauthorized, repo)},
		{name: "404", status: 404, body: errBody(KindNotFound, "gone"), kind: FailUnresolvable,
			reason: fmt.Sprintf(registry.ReasonNotFound, repo+"@"+digest)},
		{name: "413", status: 413, body: errBody(KindTooLarge, "compressed layers total 12 bytes, limit 10 bytes"),
			kind: FailQuarantine, reason: "compressed layers total 12 bytes, limit 10 bytes"},
		{name: "429", status: 429, body: errBody(KindRateLimited, "slow down"), kind: FailTransient},
		{name: "503", status: 503, body: errBody(KindBusy, "cataloguer is busy"), kind: FailTransient},
		{name: "socket missing", socket: filepath.Join(filepath.Dir(fake.socket), "missing.sock"), kind: FailTransient},
		{name: "504", status: 504, body: errBody(KindTimeout, "late"), kind: FailCounted, reason: "cataloguer timed out after 10m0s"},
		{name: "507", status: 507, body: errBody(KindScratchFull, "full"), kind: FailCounted,
			reason: "image unpacked beyond the cataloguer scratch limit"},
		{name: "500", status: 500, body: errBody(KindFailed, "syft exploded"), kind: FailCounted, reason: "cataloguer failed: syft exploded"},
		{name: "hangup", hangup: true, kind: FailCounted, reason: "cataloguer stopped while processing the image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := src
			if tc.socket != "" {
				c := cfg
				c.Socket = tc.socket
				s = NewCatalogSource(reg.Client, c)
				s.reg = reg
			}
			fake.set(tc.status, tc.body, tc.hangup)
			before := reg.reserves.Load()

			res, err := s.Acquire(ctx, req)
			require.Nil(t, res)
			require.Error(t, err)
			require.Equal(t, tc.kind, KindOf(err), err.Error())
			if tc.reason != "" {
				var ae *AcquireError
				require.True(t, errors.As(err, &ae))
				require.Equal(t, tc.reason, ae.Reason)
			}
			require.Equal(t, before+1, reg.reserves.Load(), "one Reserve per Acquire")
		})
	}
}
