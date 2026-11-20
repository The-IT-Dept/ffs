package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agent/contentstore/contentstoretest"
	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/catalog"
	"github.com/the-it-dept/ffs/internal/sbom"
)

const (
	fixtureBootID = "0b5c9a7e-5d1f-4c4e-9d55-2f6b3c1a8e90"
	hostJSON      = `{"artifacts":[],"source":{"id":"host"}}`
	imageJSON     = `{"artifacts":[],"source":{"id":"image"}}`
	storeHostPath = "/var/lib/containerd/io.containerd.content.v1.content"
	waitFor       = 10 * time.Second
)

// fastTimers shortens the schedule's units for the test.
func fastTimers(t *testing.T) {
	t.Helper()
	hb, bo, iu := heartbeatEvery, backoffBase, intervalUnit
	t.Cleanup(func() { heartbeatEvery, backoffBase, intervalUnit = hb, bo, iu })
	heartbeatEvery, backoffBase, intervalUnit = 10*time.Millisecond, 10*time.Millisecond, 100*time.Millisecond
}

// fakeController is the controller's agent API: it records reports and SBOM results and answers from funcs.
type fakeController struct {
	url     string
	reports chan wire.Report
	sboms   chan wire.SBOMResult

	mu      sync.Mutex
	config  func() (int, wire.AgentConfig)
	answer  func(r wire.Report) (int, wire.ReportResponse)
	headers func(r wire.Report) http.Header // extra headers of the report answer; nil: none
	events  []string                        // "config", the report kinds and "sbom:<id>", in arrival order
	times   []time.Time                     // when each event arrived
}

func newFakeController(t *testing.T, caFile string) *fakeController {
	t.Helper()
	ca := newCA(t, "agent-api-ca")
	leaf := newLeaf(t, ca, "127.0.0.1")
	writeTestFile(t, caFile, ca.pem)
	c := &fakeController{reports: make(chan wire.Report, 1000), sboms: make(chan wire.SBOMResult, 100)}
	c.config = func() (int, wire.AgentConfig) {
		return http.StatusOK, wire.AgentConfig{ReportIntervalSeconds: 3600, ImageListIntervalSeconds: 1, MaxReportBytes: 32 << 20}
	}
	c.answer = func(wire.Report) (int, wire.ReportResponse) {
		cfg := wire.AgentConfig{ReportIntervalSeconds: 3600, ImageListIntervalSeconds: 1, MaxReportBytes: 32 << 20}
		return http.StatusOK, wire.ReportResponse{Applied: true, Config: cfg}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+wire.PathConfig, func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		c.record("config")
		code, cfg := c.config()
		c.mu.Unlock()
		reply(w, code, cfg)
	})
	mux.HandleFunc("POST "+wire.PathReport, func(w http.ResponseWriter, r *http.Request) {
		var rep wire.Report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		c.mu.Lock()
		c.record(rep.Kind)
		answer, headers := c.answer, c.headers
		c.mu.Unlock()
		c.reports <- rep
		code, resp := answer(rep)
		if headers != nil {
			for k, v := range headers(rep) {
				w.Header()[k] = v
			}
		}
		reply(w, code, resp)
	})
	mux.HandleFunc("POST "+wire.PathSBOM, func(w http.ResponseWriter, r *http.Request) {
		var res wire.SBOMResult
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		c.mu.Lock()
		c.record("sbom:" + res.ID)
		c.mu.Unlock()
		c.sboms <- res
		w.WriteHeader(http.StatusNoContent)
	})
	c.url = tlsServer(t, mux, func() *tls.Certificate { return &leaf })
	return c
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if code >= 300 {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// record notes an event; c.mu is held.
func (c *fakeController) record(event string) {
	c.events = append(c.events, event)
	c.times = append(c.times, time.Now())
}

// log returns the events so far and when each arrived.
func (c *fakeController) log() ([]string, []time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.events), slices.Clone(c.times)
}

func (c *fakeController) setHeaders(f func(r wire.Report) http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers = f
}

func (c *fakeController) setAnswer(f func(r wire.Report) (int, wire.ReportResponse)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answer = f
}

func (c *fakeController) setConfig(f func() (int, wire.AgentConfig)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = f
}

// next returns the next report the controller received.
func (c *fakeController) next(t *testing.T) wire.Report {
	t.Helper()
	select {
	case r := <-c.reports:
		return r
	case <-time.After(waitFor):
		t.Fatal("no report arrived")
	}
	return wire.Report{}
}

// fakeRunner is the cataloguer's runner: it records jobs and answers from fn, or with fixed documents.
type fakeRunner struct {
	mu        sync.Mutex
	calls     []sbom.CatalogRequest
	fn        func(ctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error)
	active    atomic.Int32
	maxActive atomic.Int32
}

func (f *fakeRunner) run(ctx context.Context, req sbom.CatalogRequest, _ string) (*sbom.CatalogResponse, error) {
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		m := f.maxActive.Load()
		if n <= m || f.maxActive.CompareAndSwap(m, n) {
			break
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, req)
	fn := f.fn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	if req.Source == sbom.CatalogSourceHostDir {
		return &sbom.CatalogResponse{SyftJSON: json.RawMessage(hostJSON)}, nil
	}
	return &sbom.CatalogResponse{SyftJSON: json.RawMessage(imageJSON)}, nil
}

func (f *fakeRunner) setFn(fn func(ctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fn = fn
}

func (f *fakeRunner) requests() []sbom.CatalogRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// env is one agent's world: a host root, /proc, a content store with one image, a controller and a cataloguer.
type env struct {
	hostRoot, scratch, socket string
	manifest, config          string
	ctl                       *fakeController
	runner                    *fakeRunner
	opts                      Options
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fastTimers(t)
	e := &env{hostRoot: t.TempDir(), runner: &fakeRunner{}}
	writeHostFile(t, e.hostRoot, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"26.04\"\n")
	writeHostFile(t, e.hostRoot, "var/lib/dpkg/status", "Package: openssl\n")
	writeHostFile(t, e.hostRoot, "usr/bin/containerd", "containerd binary")

	old := procDir
	t.Cleanup(func() { procDir = old })
	procDir = t.TempDir()
	writeHostFile(t, procDir, "sys/kernel/osrelease", "7.0.0-34-generic\n")
	writeHostFile(t, procDir, "sys/kernel/random/boot_id", fixtureBootID+"\n")

	e.manifest, e.config = contentstoretest.WriteImage(t, e.storeDir(), testImage(t, runtime.GOARCH))

	work := t.TempDir()
	e.scratch = filepath.Join(work, "stage")
	require.NoError(t, os.MkdirAll(e.scratch, 0o750))
	sockDir, err := os.MkdirTemp("", "ffs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	e.socket = filepath.Join(sockDir, "c.sock")

	caFile, tokenFile := filepath.Join(work, "ca.crt"), filepath.Join(work, "token")
	writeTestFile(t, tokenFile, []byte("token"))
	e.ctl = newFakeController(t, caFile)
	e.opts = Options{
		Controller: e.ctl.url, CAFile: caFile, TokenFile: tokenFile, NodeName: "worker-1", HostRoot: HostRoot(e.hostRoot),
		Distribution: DistContainerd, Scratch: e.scratch, CatalogSocket: e.socket, Heartbeat: filepath.Join(work, "heartbeat"),
		MaxImageBytes: 1 << 30, Log: logr.Discard(), Jitter: func(time.Duration) time.Duration { return 0 },
	}
	return e
}

func (e *env) storeDir() string { return filepath.Join(e.hostRoot, storeHostPath) }

// testImage is a random image for linux/arch with OCI media types.
func testImage(t *testing.T, arch string) v1.Image {
	t.Helper()
	img, err := random.Image(256, 1)
	require.NoError(t, err)
	cf, err := img.ConfigFile()
	require.NoError(t, err)
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", arch
	img, err = mutate.ConfigFile(img, cf)
	require.NoError(t, err)
	return mutate.ConfigMediaType(mutate.MediaType(img, types.OCIManifestSchema1), types.OCIConfigJSON)
}

// startCataloguer serves the env's cataloguer until the test ends and waits until it answers.
func (e *env) startCataloguer(t *testing.T) {
	t.Helper()
	srv := &catalog.Server{ScratchDir: t.TempDir(), LocalRoot: e.scratch, MaxConcurrent: 1, Run: e.runner.run, Log: logr.Discard()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx, e.socket) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	probe := &http.Client{Transport: &http.Transport{DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(dctx, "unix", e.socket)
	}}}
	require.Eventually(t, func() bool {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://catalog/healthz", nil)
		resp, err := probe.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, waitFor, 10*time.Millisecond)
}

// run starts Run with the env's options until the test ends.
func (e *env) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	o := e.opts
	go func() { done <- Run(ctx, o) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(waitFor):
			t.Error("Run did not return after cancel")
		}
	})
}

func mtime(t *testing.T, p string) time.Time {
	t.Helper()
	fi, err := os.Stat(p)
	require.NoError(t, err)
	return fi.ModTime()
}

// mtimeNano is a file's mtime, 0 when it cannot be read; safe off the test goroutine.
func mtimeNano(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.ModTime().UnixNano()
}

func resolvedScratch(t *testing.T, e *env) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(e.scratch)
	require.NoError(t, err)
	return p
}

func TestRun_FullThenImagesOnlyWhenChanged(t *testing.T) {
	e := newEnv(t)
	e.startCataloguer(t)
	e.run(t)

	r := e.ctl.next(t)
	require.Equal(t, wire.KindFull, r.Kind)
	require.Equal(t, uint64(1), r.Seq)
	require.Equal(t, "worker-1", r.Node)
	require.Equal(t, fixtureBootID, r.BootID)
	require.Equal(t, "7.0.0-34-generic", r.KernelRelease)
	require.Equal(t, runtime.GOARCH, r.Arch)
	require.False(t, r.StartedAt.IsZero())
	require.NotNil(t, r.Host)
	require.Equal(t, "dpkg", r.Host.PackageDB)
	require.Equal(t, []wire.Binary{{Name: "containerd", Path: "/usr/bin/containerd", Size: int64(len("containerd binary"))}}, r.Host.Binaries)
	require.JSONEq(t, hostJSON, string(r.Host.SyftJSON))
	require.NotNil(t, r.Images)
	require.True(t, r.Images.ContentStore)
	require.Len(t, r.Images.Digests, 1)
	require.Equal(t, e.manifest, r.Images.Digests[0].Digest)
	require.Equal(t, e.config, r.Images.Digests[0].ConfigDigest)
	require.Empty(t, r.Problems)

	calls := e.runner.requests()
	require.NotEmpty(t, calls)
	require.Equal(t, sbom.CatalogSourceHostDir, calls[0].Source)
	require.Equal(t, filepath.Join(resolvedScratch(t, e), "host-1"), calls[0].Path)
	require.Equal(t, int64(MaxHostBytes), calls[0].MaxBytes)
	_, err := os.Stat(filepath.Join(e.scratch, "host-1"))
	require.ErrorIs(t, err, fs.ErrNotExist, "the host stage is removed before the report is sent")

	r = e.ctl.next(t)
	require.Equal(t, wire.KindImages, r.Kind)
	require.Equal(t, uint64(2), r.Seq)
	require.Nil(t, r.Images, "the list has not changed")
	require.Nil(t, r.Problems)
	require.Nil(t, r.Host)
	beat := mtime(t, e.opts.Heartbeat)

	contentstoretest.WriteImage(t, e.storeDir(), testImage(t, runtime.GOARCH))
	for {
		r = e.ctl.next(t)
		if r.Images != nil {
			break
		}
	}
	require.Equal(t, wire.KindImages, r.Kind)
	require.Len(t, r.Images.Digests, 2)
	r = e.ctl.next(t)
	require.Nil(t, r.Images, "the changed list was accepted")
	require.True(t, mtime(t, e.opts.Heartbeat).After(beat), "the heartbeat is touched after every report")
}

func TestRun_ImagesResentUntilApplied(t *testing.T) {
	e := newEnv(t)
	e.startCataloguer(t)
	refused := atomic.Bool{}
	e.ctl.setAnswer(func(r wire.Report) (int, wire.ReportResponse) {
		cfg := wire.AgentConfig{ReportIntervalSeconds: 3600, ImageListIntervalSeconds: 1}
		if r.Kind == wire.KindImages && r.Images != nil && refused.CompareAndSwap(false, true) {
			return http.StatusOK, wire.ReportResponse{Applied: false, Config: cfg}
		}
		return http.StatusOK, wire.ReportResponse{Applied: true, Config: cfg}
	})
	e.run(t)
	require.Equal(t, wire.KindFull, e.ctl.next(t).Kind)
	require.Nil(t, e.ctl.next(t).Images)

	contentstoretest.WriteImage(t, e.storeDir(), testImage(t, runtime.GOARCH))
	var r wire.Report
	for r.Images == nil {
		r = e.ctl.next(t)
	}
	require.Len(t, r.Images.Digests, 2)
	r = e.ctl.next(t)
	require.NotNil(t, r.Images, "the controller did not apply the changed list, so it is sent again")
	require.Len(t, r.Images.Digests, 2)
	require.Nil(t, e.ctl.next(t).Images)
}

func TestRun_NoContentStore(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		e := newEnv(t)
		e.startCataloguer(t)
		require.NoError(t, os.RemoveAll(e.storeDir()))
		e.opts.ContentStore = e.storeDir()
		e.run(t)
		r := e.ctl.next(t)
		require.Equal(t, &wire.Images{ContentStore: false}, r.Images)
		require.Contains(t, r.Problems, wire.Problem{Code: "content_store", Path: storeHostPath,
			Detail: "no containerd content store at " + storeHostPath})
		require.NotNil(t, r.Host, "the host inventory does not depend on the content store")
	})
	t.Run("crio", func(t *testing.T) {
		e := newEnv(t)
		e.startCataloguer(t)
		e.opts.Distribution = DistCRIO
		e.run(t)
		r := e.ctl.next(t)
		require.Equal(t, wire.KindFull, r.Kind)
		require.Equal(t, &wire.Images{ContentStore: false}, r.Images)
		require.Contains(t, r.Problems, wire.Problem{Code: "content_store", Detail: "no containerd content store (CRI-O)"})
		r = e.ctl.next(t)
		require.Equal(t, wire.KindImages, r.Kind)
		require.Nil(t, r.Images, "nothing changed since the accepted full report")
	})
}

func TestRun_HostSBOMOverLimit(t *testing.T) {
	big := `{"artifacts":[],"descriptor":{"name":"` + strings.Repeat("x", 2048) + `"}}`
	t.Run("over the limit", func(t *testing.T) {
		e := newEnv(t)
		e.runner.setFn(func(context.Context, sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
			return &sbom.CatalogResponse{SyftJSON: json.RawMessage(big)}, nil
		})
		e.ctl.setConfig(func() (int, wire.AgentConfig) {
			return http.StatusOK, wire.AgentConfig{ReportIntervalSeconds: 3600, ImageListIntervalSeconds: 1, MaxReportBytes: 1024}
		})
		e.startCataloguer(t)
		e.run(t)
		r := e.ctl.next(t)
		require.Nil(t, r.Host)
		require.Contains(t, r.Problems, wire.Problem{Code: "catalog",
			Detail: fmt.Sprintf("host SBOM of %d bytes exceeds the report limit 1024", len(big))})
		require.NotNil(t, r.Images)
	})
	t.Run("config without intervals", func(t *testing.T) {
		e := newEnv(t)
		e.runner.setFn(func(context.Context, sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
			return &sbom.CatalogResponse{SyftJSON: json.RawMessage(big)}, nil
		})
		e.ctl.setConfig(func() (int, wire.AgentConfig) { return http.StatusOK, wire.AgentConfig{MaxReportBytes: 1024} })
		e.startCataloguer(t)
		e.run(t)
		r := e.ctl.next(t)
		require.NotNil(t, r.Host, "the fallback limit of 32 MiB applies")
		require.JSONEq(t, big, string(r.Host.SyftJSON))
	})
}

func TestRun_HeartbeatDuringSlowFullReport(t *testing.T) {
	e := newEnv(t)
	var before, after atomic.Int64
	e.runner.setFn(func(ctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
		if req.Source == sbom.CatalogSourceHostDir && before.Load() == 0 {
			before.Store(mtimeNano(e.opts.Heartbeat))
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
			}
			after.Store(mtimeNano(e.opts.Heartbeat))
		}
		return &sbom.CatalogResponse{SyftJSON: json.RawMessage(hostJSON)}, nil
	})
	e.startCataloguer(t)
	e.run(t)
	r := e.ctl.next(t)
	require.Equal(t, wire.KindFull, r.Kind)
	require.NotNil(t, r.Host)
	require.Greater(t, after.Load(), before.Load(), "the heartbeat advanced while the host was catalogued")
}

func TestRun_ReportFailureBacksOff(t *testing.T) {
	e := newEnv(t)
	e.startCataloguer(t)
	e.ctl.setAnswer(func(wire.Report) (int, wire.ReportResponse) {
		return http.StatusInternalServerError, wire.ReportResponse{}
	})
	start := time.Now()
	e.run(t)
	var beats []time.Time
	for want := uint64(1); want <= 3; want++ {
		r := e.ctl.next(t)
		require.Equal(t, want, r.Seq, "Seq increases per attempt")
		require.Equal(t, wire.KindFull, r.Kind, "a failed full report is retried as a full report")
		require.Eventually(t, func() bool { _, err := os.Stat(e.opts.Heartbeat); return err == nil }, waitFor, time.Millisecond)
		beats = append(beats, mtime(t, e.opts.Heartbeat))
	}
	require.Less(t, time.Since(start), time.Second, "three attempts within a second")
	require.Eventually(t, func() bool { return mtime(t, e.opts.Heartbeat).After(beats[0]) }, waitFor, 5*time.Millisecond,
		"the heartbeat is touched after each failed attempt")
}

func TestRun_HostRetriedOnBackoffWhenCataloguerAbsentAtStart(t *testing.T) {
	e := newEnv(t)
	ready := make(chan struct{})
	e.ctl.setAnswer(func(r wire.Report) (int, wire.ReportResponse) {
		if r.Seq == 1 {
			<-ready // the test starts the cataloguer before the agent hears back, so the retry finds it
		}
		return http.StatusOK, wire.ReportResponse{Applied: true, Config: wire.AgentConfig{ReportIntervalSeconds: 3600, ImageListIntervalSeconds: 600}}
	})
	e.run(t)
	r := e.ctl.next(t)
	require.Nil(t, r.Host)
	i := slices.IndexFunc(r.Problems, func(p wire.Problem) bool { return p.Code == "catalog" })
	require.GreaterOrEqual(t, i, 0, "%v", r.Problems)
	require.True(t, strings.HasPrefix(r.Problems[i].Detail, "busy: cataloguer unavailable: "), r.Problems[i].Detail)
	e.startCataloguer(t)
	start := time.Now()
	close(ready)

	r = e.ctl.next(t)
	require.Equal(t, wire.KindFull, r.Kind, "the host part is retried on the backoff, not the report interval")
	require.NotNil(t, r.Host)
	require.Less(t, time.Since(start), time.Second)
}

func TestNextBackoff(t *testing.T) {
	var got []time.Duration
	d := time.Duration(0)
	for range 7 {
		d = nextBackoff(d)
		got = append(got, d)
	}
	require.Equal(t, []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second,
		300 * time.Second, 300 * time.Second}, got)
}

func TestJittered(t *testing.T) {
	for _, r := range []func(time.Duration) time.Duration{
		func(time.Duration) time.Duration { return 0 },
		func(m time.Duration) time.Duration { return m / 2 },
		func(m time.Duration) time.Duration { return m },
	} {
		got := jittered(100*time.Second, 10, r)
		require.GreaterOrEqual(t, got, 90*time.Second)
		require.LessOrEqual(t, got, 110*time.Second)
	}
	require.Equal(t, 90*time.Second, jittered(100*time.Second, 10, func(time.Duration) time.Duration { return 0 }))
	require.Equal(t, 110*time.Second, jittered(100*time.Second, 10, func(m time.Duration) time.Duration { return m }))
	require.Equal(t, 100*time.Second, jittered(100*time.Second, 0, func(m time.Duration) time.Duration { return m }))
}

func TestRun_RequiresNodeName(t *testing.T) {
	err := Run(context.Background(), Options{Controller: "https://ffs-agent-api.ffs.svc:8444"})
	require.EqualError(t, err, "node name is required (--node-name or NODE_NAME)")
	err = Run(context.Background(), Options{Controller: "http://ffs-agent-api", NodeName: "worker-1"})
	require.EqualError(t, err, "controller URL must be https")
}
