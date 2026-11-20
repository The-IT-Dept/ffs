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
	"strconv"
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
	// jobDirPrefix starts the name of every per-job scratch directory, so the server can tell its own
	// leftovers from anything else under ScratchDir.
	jobDirPrefix = "job-"
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
	sbom.KindUnavailable:  http.StatusBadGateway,
	sbom.KindFailed:       http.StatusInternalServerError,
	sbom.KindBusy:         http.StatusServiceUnavailable,
	sbom.KindTimeout:      http.StatusGatewayTimeout,
	sbom.KindScratchFull:  http.StatusInsufficientStorage,
}

// Runner runs one job with jobDir as its scratch directory.
type Runner func(ctx context.Context, req sbom.CatalogRequest, jobDir string) (*sbom.CatalogResponse, error)

// Server serves catalog jobs: POST /v1/catalog and GET /healthz.
type Server struct {
	ScratchDir    string        // emptyDir mount; created (0700) when missing
	ScratchLimit  int64         // total bytes across jobs; <= 0 is unlimited
	MaxConcurrent int           // default 2
	Run           Runner        // default ExecRunner
	Poll          time.Duration // watchdog interval, default 1s
	// LocalRoot is the directory local sources (oci-dir, host-dir) must resolve inside, after
	// symlinks; "" refuses them.
	LocalRoot string
	Log       logr.Logger

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

// ListenAndServe serves on the unix socket until ctx is done. A stale socket file is replaced,
// ScratchDir is created when missing, and job directories left in it by a previous run are removed.
// Jobs still running at shutdown are killed.
func (s *Server) ListenAndServe(ctx context.Context, socket string) error {
	if err := os.Remove(socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing stale socket: %w", err)
	}
	if s.ScratchDir != "" {
		if err := os.MkdirAll(s.ScratchDir, 0o700); err != nil {
			return fmt.Errorf("creating scratch directory: %w", err)
		}
	}
	if err := s.removeStaleJobs(); err != nil {
		return err
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

// removeStaleJobs deletes the job directories a previous run left in ScratchDir. The scratch volume
// outlives the container, so the partial extractions of a cataloguer that was killed (an out-of-memory
// kill takes the whole container) would otherwise stay on disk, unseen by the scratch watchdog, until
// the volume's size limit evicts the pod.
func (s *Server) removeStaleJobs() error {
	if s.ScratchDir == "" {
		return nil
	}
	entries, err := os.ReadDir(s.ScratchDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading scratch directory: %w", err)
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), jobDirPrefix) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.ScratchDir, e.Name())); err != nil {
			return fmt.Errorf("removing stale job directory: %w", err)
		}
		removed++
	}
	if removed > 0 {
		s.Log.Info("removed job directories left by a previous run", "count", removed)
	}
	return nil
}

func (s *Server) serveCatalog(w http.ResponseWriter, r *http.Request) {
	var req sbom.CatalogRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
		s.reply(w, jobLabel(req), nil, &WorkError{Kind: sbom.KindBadRequest, Msg: "invalid request: " + err.Error()})
		return
	}
	var err *WorkError
	switch req.Source {
	case "", sbom.CatalogSourceRegistry:
		err = validate(req)
	case sbom.CatalogSourceOCIDir, sbom.CatalogSourceHostDir:
		err = s.validateLocal(&req)
	default:
		err = badRequest("unknown source %q", req.Source)
	}
	if err != nil {
		s.reply(w, jobLabel(req), nil, err)
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.reply(w, jobLabel(req), nil, &WorkError{Kind: sbom.KindBusy, Msg: "cataloguer is busy"})
		return
	}
	resp, rerr := func() (*sbom.CatalogResponse, error) {
		defer func() { <-s.sem }()
		return s.runJob(r.Context(), req)
	}()
	s.reply(w, jobLabel(req), resp, rerr)
}

func badRequest(format string, a ...any) *WorkError {
	return &WorkError{Kind: sbom.KindBadRequest, Msg: fmt.Sprintf(format, a...)}
}

// validate checks a registry request.
func validate(req sbom.CatalogRequest) *WorkError {
	if !strings.Contains(req.Ref, "@sha256:") {
		return badRequest("ref %q is not pinned by a sha256 digest", req.Ref)
	}
	if _, err := name.NewDigest(req.Ref); err != nil {
		return badRequest("ref %q: %v", req.Ref, err)
	}
	if _, err := image.NewPlatform(req.Platform); err != nil {
		return badRequest("%v", err)
	}
	return validateLimits(req)
}

// validateLocal checks a local-source request and rewrites req.Path to its resolved form. The path
// must resolve, after symlinks, strictly below LocalRoot, which is resolved on every request since
// the node agent's collector creates it after the cataloguer starts. An oci-dir needs a platform;
// a host-dir takes none.
func (s *Server) validateLocal(req *sbom.CatalogRequest) *WorkError {
	if s.LocalRoot == "" {
		return badRequest("local sources are disabled: the cataloguer has no --local-root")
	}
	if !filepath.IsAbs(req.Path) {
		return badRequest("path %q must be absolute", req.Path)
	}
	root, err := filepath.EvalSymlinks(s.LocalRoot)
	if err != nil {
		return badRequest("local root cannot be resolved: %v", err)
	}
	p, err := filepath.EvalSymlinks(req.Path)
	if err != nil {
		return badRequest("path %q cannot be resolved: %v", req.Path, err)
	}
	if !strings.HasPrefix(p, root+string(filepath.Separator)) {
		return badRequest("path %q is outside the local root", req.Path)
	}
	req.Path = p
	if req.Source == sbom.CatalogSourceOCIDir {
		if _, err := image.NewPlatform(req.Platform); err != nil {
			return badRequest("%v", err)
		}
	}
	return validateLimits(*req)
}

// validateLimits checks the limits every request carries.
func validateLimits(req sbom.CatalogRequest) *WorkError {
	if req.MaxBytes <= 0 {
		return badRequest("maxBytes must be > 0")
	}
	if req.TimeoutSeconds <= 0 {
		return badRequest("timeoutSeconds must be > 0")
	}
	return nil
}

// isLocal reports whether req reads a local source rather than pulling Ref.
func isLocal(req sbom.CatalogRequest) bool {
	return req.Source == sbom.CatalogSourceOCIDir || req.Source == sbom.CatalogSourceHostDir
}

// jobLabel names a job in logs: its ref, or for a local source its source and directory name.
func jobLabel(req sbom.CatalogRequest) string {
	if req.Ref != "" || req.Path == "" {
		return req.Ref
	}
	return req.Source + ":" + filepath.Base(req.Path)
}

// runJob pre-checks the image size (the compressed layers in the registry, or the bytes of a local
// source), then runs the job in its own scratch directory under the job timeout and the scratch
// watchdog. The directory is gone by the time it returns.
func (s *Server) runJob(parent context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	ctx, stop := context.WithTimeoutCause(ctx, time.Duration(req.TimeoutSeconds)*time.Second, errTimeout)
	defer stop()

	if isLocal(req) {
		if size := dirSize(req.Path); size > req.MaxBytes {
			return nil, &WorkError{Kind: sbom.KindTooLarge, Msg: fmt.Sprintf("local source holds %d bytes, limit %d bytes", size, req.MaxBytes)}
		}
	} else {
		size, err := compressedSize(ctx, req)
		if err != nil {
			return nil, s.jobError(ctx, err)
		}
		if size > req.MaxBytes {
			return nil, &WorkError{Kind: sbom.KindTooLarge, Msg: fmt.Sprintf("compressed layers total %d bytes, limit %d bytes", size, req.MaxBytes)}
		}
	}

	id := make([]byte, 8)
	_, _ = rand.Read(id)
	dir := filepath.Join(s.ScratchDir, jobDirPrefix+hex.EncodeToString(id))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, &WorkError{Kind: sbom.KindFailed, Msg: "creating job directory: " + err.Error()}
	}
	defer func() { _ = os.RemoveAll(dir) }()
	untrack := s.track(&job{ref: jobLabel(req), dir: dir, ctx: ctx, cancel: cancel})
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

// execOptions are the ExecRunner options.
type execOptions struct {
	nice     int
	memLimit int64
}

// ExecOption configures ExecRunner.
type ExecOption func(*execOptions)

// WithNice runs each worker at nice value n (0 to 19), so cataloguing yields the CPU to the node's
// workloads. 0 leaves the priority alone.
func WithNice(n int) ExecOption { return func(o *execOptions) { o.nice = n } }

// WithMemoryLimit sets each worker's GOMEMLIMIT to n bytes, in place of the server's own, which the
// worker would otherwise inherit. The worker shares the container's memory limit with the server, so
// it gets that limit less what the server needs. 0 leaves the worker the server's GOMEMLIMIT.
func WithMemoryLimit(n int64) ExecOption { return func(o *execOptions) { o.memLimit = n } }

// ExecRunner runs each job as `self catalog worker` in its own process group, with TMPDIR set to the
// job directory. The request (credentials included) goes on stdin, never in argv or the
// environment; the response comes back on stdout; stderr is discarded. When ctx ends, the whole
// process group is killed.
func ExecRunner(self string, opts ...ExecOption) Runner {
	var o execOptions
	for _, opt := range opts {
		opt(&o)
	}
	return func(ctx context.Context, req sbom.CatalogRequest, jobDir string) (*sbom.CatalogResponse, error) {
		in, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, self, "catalog", "worker") //nolint:gosec // G204: self is this binary
		cmd.Env = append(os.Environ(), "TMPDIR="+jobDir)
		if o.memLimit > 0 {
			cmd.Env = append(cmd.Env, "GOMEMLIMIT="+strconv.FormatInt(o.memLimit, 10))
		}
		cmd.Stdin = bytes.NewReader(in)
		cmd.Stdout = &out
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = workerWaitDelay

		err = cmd.Start()
		if err == nil && o.nice > 0 {
			// The worker's process group, not its process: nice is per thread on Linux, and the
			// worker's Go runtime has started threads before this call. PRIO_PGRP sets every thread of
			// the group, and threads created later inherit it.
			if perr := syscall.Setpriority(syscall.PRIO_PGRP, cmd.Process.Pid, o.nice); perr != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				_ = cmd.Wait()
				return nil, &WorkError{Kind: sbom.KindFailed, Msg: "setting worker priority: " + perr.Error()}
			}
		}
		if err == nil {
			err = cmd.Wait()
		}
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
			return nil, &WorkError{Kind: sbom.KindFailed, Msg: signalMessage(ws.Signal())}
		}
		return nil, &WorkError{Kind: sbom.KindFailed, Msg: fmt.Sprintf("cataloguer exited with status %d", ee.ExitCode())}
	}
}

// signalMessage describes a worker that a signal ended, naming the signal once: "cataloguer worker
// ended by signal 9 (killed)".
func signalMessage(sig syscall.Signal) string {
	return fmt.Sprintf("cataloguer worker ended by signal %d (%s)", int(sig), sig)
}
