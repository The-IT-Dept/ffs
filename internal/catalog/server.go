package catalog

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/version"
)

const (
	defaultMaxConcurrent = 2
	defaultPoll          = time.Second
	maxRequestBody       = 64 << 10
	workerWaitDelay      = 5 * time.Second
	shutdownGrace        = 10 * time.Second
	readHeaderTimeout    = 10 * time.Second
)

var (
	errTimeout     = errors.New("catalog: job timed out")
	errScratchFull = errors.New("catalog: job exceeded the scratch limit")
)

// kindStatus is the HTTP status answered for each error kind.
var kindStatus = map[string]int{
	sbom.KindBadRequest:   http.StatusBadRequest,
	sbom.KindUnauthorized: http.StatusUnauthorized,
	sbom.KindNotFound:     http.StatusNotFound,
	sbom.KindTooLarge:     http.StatusRequestEntityTooLarge,
	sbom.KindRateLimited:  http.StatusTooManyRequests,
	sbom.KindFailed:       http.StatusInternalServerError,
	sbom.KindBusy:         http.StatusServiceUnavailable,
	sbom.KindTimeout:      http.StatusGatewayTimeout,
	sbom.KindScratchFull:  http.StatusInsufficientStorage,
}

// Runner runs one job with jobDir as its scratch directory.
type Runner func(ctx context.Context, req sbom.CatalogRequest, jobDir string) (*sbom.CatalogResponse, error)

// Server serves catalog jobs: POST /v1/catalog and GET /healthz.
type Server struct {
	ScratchDir    string        // emptyDir mount
	ScratchLimit  int64         // total bytes across jobs; <= 0 is unlimited
	MaxConcurrent int           // default 2
	Run           Runner        // default ExecRunner
	Poll          time.Duration // watchdog interval, default 1s
	Log           logr.Logger

	once     sync.Once
	sem      chan struct{}
	mu       sync.Mutex
	jobs     map[*job]struct{}
	watching bool
}

// job is a running job as the scratch watchdog sees it.
type job struct {
	ref    string
	dir    string
	ctx    context.Context
	cancel context.CancelCauseFunc
}

func (s *Server) init() {
	s.once.Do(func() {
		if s.MaxConcurrent <= 0 {
			s.MaxConcurrent = defaultMaxConcurrent
		}
		if s.Poll <= 0 {
			s.Poll = defaultPoll
		}
		if s.Run == nil {
			self, err := os.Executable()
			if err != nil {
				self = os.Args[0]
			}
			s.Run = ExecRunner(self)
		}
		s.sem = make(chan struct{}, s.MaxConcurrent)
		s.jobs = map[*job]struct{}{}
	})
}

// Handler returns the server's routes.
func (s *Server) Handler() http.Handler {
	s.init()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/catalog", s.serveCatalog)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

// ListenAndServe serves on the unix socket until ctx is done. A stale socket file is replaced. Jobs
// still running at shutdown are killed.
func (s *Server) ListenAndServe(ctx context.Context, socket string) error {
	if err := os.Remove(socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing stale socket: %w", err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", socket)
	if err != nil {
		return err
	}
	// The controller container shares the socket's emptyDir and the pod's group.
	if err := os.Chmod(socket, 0o660); err != nil { //nolint:gosec // G302: group access is how the controller connects
		_ = ln.Close()
		return err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	s.Log.Info("cataloguer listening", "socket", socket)
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		<-stopped
		return nil
	}
	return err
}

func (s *Server) serveCatalog(w http.ResponseWriter, r *http.Request) {
	var req sbom.CatalogRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
		s.reply(w, req.Ref, nil, &WorkError{Kind: sbom.KindBadRequest, Msg: "invalid request: " + err.Error()})
		return
	}
	if err := validate(req); err != nil {
		s.reply(w, req.Ref, nil, err)
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.reply(w, req.Ref, nil, &WorkError{Kind: sbom.KindBusy, Msg: "cataloguer is busy"})
		return
	}
	resp, err := func() (*sbom.CatalogResponse, error) {
		defer func() { <-s.sem }()
		return s.runJob(r.Context(), req)
	}()
	s.reply(w, req.Ref, resp, err)
}

func validate(req sbom.CatalogRequest) *WorkError {
	bad := func(format string, a ...any) *WorkError {
		return &WorkError{Kind: sbom.KindBadRequest, Msg: fmt.Sprintf(format, a...)}
	}
	if !strings.Contains(req.Ref, "@sha256:") {
		return bad("ref %q is not pinned by a sha256 digest", req.Ref)
	}
	if _, err := name.NewDigest(req.Ref); err != nil {
		return bad("ref %q: %v", req.Ref, err)
	}
	if _, err := image.NewPlatform(req.Platform); err != nil {
		return bad("%v", err)
	}
	if req.MaxBytes <= 0 {
		return bad("maxBytes must be > 0")
	}
	if req.TimeoutSeconds <= 0 {
		return bad("timeoutSeconds must be > 0")
	}
	return nil
}

// runJob pre-checks the image size, then runs the job in its own scratch directory under the job
// timeout and the scratch watchdog. The directory is gone by the time it returns.
func (s *Server) runJob(parent context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	ctx, stop := context.WithTimeoutCause(ctx, time.Duration(req.TimeoutSeconds)*time.Second, errTimeout)
	defer stop()

	size, err := compressedSize(ctx, req)
	if err != nil {
		return nil, s.jobError(ctx, err)
	}
	if size > req.MaxBytes {
		return nil, &WorkError{Kind: sbom.KindTooLarge, Msg: fmt.Sprintf("compressed layers total %d bytes, limit %d bytes", size, req.MaxBytes)}
	}

	id := make([]byte, 8)
	_, _ = rand.Read(id)
	dir := filepath.Join(s.ScratchDir, hex.EncodeToString(id))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, &WorkError{Kind: sbom.KindFailed, Msg: "creating job directory: " + err.Error()}
	}
	defer func() { _ = os.RemoveAll(dir) }()
	untrack := s.track(&job{ref: req.Ref, dir: dir, ctx: ctx, cancel: cancel})
	defer untrack()

	resp, err := s.Run(ctx, req, dir)
	if err != nil {
		return nil, s.jobError(ctx, err)
	}
	return resp, nil
}

// jobError classifies a failed job, giving the job's own limits precedence over what the runner saw.
func (s *Server) jobError(ctx context.Context, err error) *WorkError {
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errScratchFull):
		return &WorkError{Kind: sbom.KindScratchFull, Msg: "image unpacked beyond the scratch limit"}
	case errors.Is(cause, errTimeout):
		return &WorkError{Kind: sbom.KindTimeout, Msg: "cataloguing did not finish in time"}
	case ctx.Err() != nil:
		return &WorkError{Kind: sbom.KindBusy, Msg: "cataloguer is shutting down"}
	}
	return workError(err)
}

// compressedSize sums the compressed layer sizes in the image's manifest.
func compressedSize(ctx context.Context, req sbom.CatalogRequest) (int64, error) {
	ref, err := name.NewDigest(req.Ref)
	if err != nil {
		return 0, err
	}
	p, err := v1.ParsePlatform(req.Platform)
	if err != nil {
		return 0, err
	}
	img, err := remote.Image(ref,
		remote.WithAuth(authenticator(req.Auth)),
		remote.WithPlatform(*p),
		remote.WithContext(ctx),
		remote.WithUserAgent(version.UserAgent()))
	if err != nil {
		return 0, err
	}
	m, err := img.Manifest()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, l := range m.Layers {
		total += l.Size
	}
	return total, nil
}

// reply writes the job's outcome and logs it with the ref and kind only.
func (s *Server) reply(w http.ResponseWriter, ref string, resp *sbom.CatalogResponse, err error) {
	if err == nil {
		s.Log.Info("catalogued image", "ref", ref)
		writeJSON(w, http.StatusOK, resp)
		return
	}
	we := workError(err)
	status, ok := kindStatus[we.Kind]
	if !ok {
		status = http.StatusInternalServerError
	}
	s.Log.Info("catalog job failed", "ref", ref, "kind", we.Kind)
	writeJSON(w, status, sbom.CatalogError{Kind: we.Kind, Error: we.Msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// track registers j with the scratch watchdog, starting it if it is not running.
func (s *Server) track(j *job) (untrack func()) {
	s.mu.Lock()
	s.jobs[j] = struct{}{}
	if !s.watching && s.ScratchLimit > 0 {
		s.watching = true
		go s.watch()
	}
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.jobs, j)
		s.mu.Unlock()
	}
}

// watch measures the live jobs' directories every Poll until no job is left. While their total is
// over ScratchLimit, it cancels the job with the largest directory.
func (s *Server) watch() {
	t := time.NewTicker(s.Poll)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		if len(s.jobs) == 0 {
			s.watching = false
			s.mu.Unlock()
			return
		}
		live := make([]*job, 0, len(s.jobs))
		for j := range s.jobs {
			// A cancelled job's directory is about to be removed; it no longer counts.
			if j.ctx.Err() == nil {
				live = append(live, j)
			}
		}
		s.mu.Unlock()

		var total, most int64
		var largest *job
		for _, j := range live {
			n := dirSize(j.dir)
			total += n
			if largest == nil || n > most {
				largest, most = j, n
			}
		}
		if largest != nil && total > s.ScratchLimit {
			largest.cancel(errScratchFull)
			s.Log.Info("scratch limit reached, stopping the largest job", "ref", largest.ref, "kind", sbom.KindScratchFull)
		}
	}
}

// dirSize is the total size of the regular files under dir. Files that vanish mid-walk are skipped.
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil //nolint:nilerr // a file removed mid-walk is skipped, not fatal
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// ExecRunner runs each job as `self catalog worker` in its own process group, with TMPDIR set to the
// job directory. The request (credentials included) goes on stdin, never in argv or the
// environment; the response comes back on stdout; stderr is discarded. When ctx ends, the whole
// process group is killed.
func ExecRunner(self string) Runner {
	return func(ctx context.Context, req sbom.CatalogRequest, jobDir string) (*sbom.CatalogResponse, error) {
		in, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, self, "catalog", "worker") //nolint:gosec // G204: self is this binary
		cmd.Env = append(os.Environ(), "TMPDIR="+jobDir)
		cmd.Stdin = bytes.NewReader(in)
		cmd.Stdout = &out
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = workerWaitDelay

		err = cmd.Run()
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if err == nil {
			var resp sbom.CatalogResponse
			if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
				return nil, &WorkError{Kind: sbom.KindFailed, Msg: "cataloguer returned an unreadable response"}
			}
			return &resp, nil
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, &WorkError{Kind: sbom.KindFailed, Msg: "starting cataloguer: " + err.Error()}
		}
		var ce sbom.CatalogError
		if json.Unmarshal(out.Bytes(), &ce) == nil && ce.Kind != "" {
			return nil, &WorkError{Kind: ce.Kind, Msg: ce.Error}
		}
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return nil, &WorkError{Kind: sbom.KindFailed, Msg: fmt.Sprintf("cataloguer killed by %s", ws.Signal())}
		}
		return nil, &WorkError{Kind: sbom.KindFailed, Msg: fmt.Sprintf("cataloguer exited with status %d", ee.ExitCode())}
	}
}
