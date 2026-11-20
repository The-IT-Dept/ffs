package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/the-it-dept/ffs/internal/agent/contentstore"
	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/catalog"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/version"
)

// MaxHostBytes caps the staged host inputs (os-release, package databases, binaries), independent of
// --max-image-bytes, so a small image limit never drops host binaries.
const MaxHostBytes = 512 << 20

const (
	// startJitter spreads the first full reports of a DaemonSet rollout.
	startJitter = 30 * time.Second
	// configTimeout bounds the start-up config fetch.
	configTimeout = 10 * time.Second
	// catalogClientTimeout bounds one cataloguer call; each job is bounded by its own deadline first.
	catalogClientTimeout = 31 * time.Minute
	// hostCatalogTimeout is the cataloguer's limit for the host SBOM.
	hostCatalogTimeout = 10 * time.Minute
	// fullReportTimeout bounds building and sending one full report, so a wedged one lets the heartbeat go stale.
	fullReportTimeout = 25 * time.Minute
	// maxBackoff caps the failed-report backoff.
	maxBackoff = 5 * time.Minute
)

var (
	// backoffBase is the first failed-report backoff; tests shorten it.
	backoffBase = 10 * time.Second
	// intervalUnit is the length of one second of the controller's intervals; tests shorten it.
	intervalUnit = time.Second
)

// fallbackConfig is used until the controller answers.
var fallbackConfig = wire.AgentConfig{ReportIntervalSeconds: 21600, ImageListIntervalSeconds: 300, JitterPercent: 10,
	MaxReportBytes: 32 << 20}

// Options configures Run. The chart sets them through `ffs agent` flags.
type Options struct {
	Controller, CAFile, TokenFile, NodeName string
	HostRoot                                HostRoot
	Distribution                            Distribution
	// ContentStore is the container path of containerd's content store; "" means HostRoot plus the
	// distribution's path, and stays "" (no scan) for CRI-O.
	ContentStore                      string
	Scratch, CatalogSocket, Heartbeat string
	MaxImageBytes                     int64
	Now                               func() time.Time
	Log                               logr.Logger
	ExtraBinDirs                      []string                              // host dirs searched for BinaryNames after PathsFor's BinDirs
	Jitter                            func(max time.Duration) time.Duration // nil: uniform random in [0, max]
}

// agent is one Run: the schedule's state and its collaborators.
type agent struct {
	o            Options
	client       *Client
	cat          *catalog.SocketClient
	store        *contentstore.Store // nil: no content store (CRI-O)
	storeHost    string              // host path of the content store
	paths        HostPaths
	bootID       string
	kernel       string
	started      time.Time
	cfg          wire.AgentConfig
	seq          uint64
	acceptedHash [sha256.Size]byte // hash of the last Images the controller applied
	accepted     bool
	hostBackoff  time.Duration
}

// Run sends reports until ctx ends: a full report at start (after up to 30s of jitter) and then every
// report interval, an images report every image-list interval, and the work the controller hands back.
func Run(ctx context.Context, o Options) error {
	a, err := newAgent(ctx, o)
	if err != nil {
		return err
	}
	a.loop(ctx)
	return nil
}

func newAgent(ctx context.Context, o Options) (*agent, error) {
	if o.NodeName == "" {
		return nil, errors.New("node name is required (--node-name or NODE_NAME)")
	}
	client, err := NewClient(o.Controller, o.CAFile, o.TokenFile)
	if err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Jitter == nil {
		o.Jitter = func(max time.Duration) time.Duration {
			if max <= 0 {
				return 0
			}
			return time.Duration(rand.Int64N(int64(max) + 1)) //nolint:gosec // G404: schedule jitter
		}
	}
	a := &agent{o: o, client: client, cat: catalog.NewSocketClient(o.CatalogSocket, catalogClientTimeout), started: o.Now()}
	if a.bootID, err = BootID(); err != nil {
		return nil, err
	}
	if a.kernel, err = KernelRelease(); err != nil {
		return nil, err
	}
	a.paths = PathsFor(o.Distribution)
	a.paths.BinDirs = append(a.paths.BinDirs, o.ExtraBinDirs...)
	switch {
	case o.ContentStore != "":
		a.store = contentstore.Open(o.ContentStore)
		a.storeHost = o.ContentStore
		if rel, ok := strings.CutPrefix(o.ContentStore, strings.TrimRight(string(o.HostRoot), "/")); ok && strings.HasPrefix(rel, "/") {
			a.storeHost = rel
		}
	case a.paths.ContentStore != "":
		a.store = contentstore.Open(o.HostRoot.join(a.paths.ContentStore))
		a.storeHost = a.paths.ContentStore
	}
	if err := a.cleanScratch(); err != nil {
		return nil, err
	}
	a.touch()
	cctx, cancel := context.WithTimeout(ctx, configTimeout)
	defer cancel()
	a.cfg = fallbackConfig
	if cfg, err := client.Config(cctx); err != nil {
		o.Log.Error(err, "fetching the agent config; using defaults until the controller answers")
	} else {
		a.adopt(cfg)
	}
	return a, nil
}

// cleanScratch creates the scratch dir and removes the stage dirs a previous run left.
func (a *agent) cleanScratch() error {
	if err := os.MkdirAll(a.o.Scratch, 0o755); err != nil { //nolint:gosec // G301: the non-root cataloguer reads staged files
		return err
	}
	entries, err := os.ReadDir(a.o.Scratch)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "host-") || strings.HasPrefix(e.Name(), "work-") {
			if err := os.RemoveAll(filepath.Join(a.o.Scratch, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *agent) touch() {
	if err := touchHeartbeat(a.o.Heartbeat); err != nil {
		a.o.Log.Error(err, "touching the heartbeat")
	}
}

// adopt takes the controller's config when its intervals are set.
func (a *agent) adopt(cfg wire.AgentConfig) {
	if cfg.ReportIntervalSeconds > 0 && cfg.ImageListIntervalSeconds > 0 {
		a.cfg = cfg
	}
}

func (a *agent) reportInterval() time.Duration {
	return time.Duration(a.cfg.ReportIntervalSeconds) * intervalUnit
}

func (a *agent) imageInterval() time.Duration {
	return time.Duration(a.cfg.ImageListIntervalSeconds) * intervalUnit
}

// maxImageBytes is --max-image-bytes, lowered to the controller's limit when that is set and smaller.
func (a *agent) maxImageBytes() int64 {
	if m := a.cfg.MaxImageBytes; m > 0 && m < a.o.MaxImageBytes {
		return m
	}
	return a.o.MaxImageBytes
}

func (a *agent) loop(ctx context.Context) {
	nextFull := a.o.Now().Add(a.o.Jitter(startJitter))
	nextImages := nextFull.Add(jittered(a.imageInterval(), a.cfg.JitterPercent, a.o.Jitter))
	var backoff time.Duration
	for {
		due := nextImages
		if nextFull.Before(due) || nextFull.Equal(due) {
			due = nextFull
		}
		if !a.sleepUntil(ctx, due) {
			return
		}
		now := a.o.Now()
		kind := wire.KindImages
		if !now.Before(nextFull) {
			kind = wire.KindFull
		}
		resp, sent, hostRetry, err := a.send(ctx, kind)
		a.touch()
		if ctx.Err() != nil {
			return
		}
		now = a.o.Now()
		if err != nil {
			backoff = nextBackoff(backoff)
			a.o.Log.Error(err, "sending a report", "kind", kind, "seq", a.seq, "retryIn", backoff)
			if kind == wire.KindFull {
				nextFull = now.Add(backoff)
			} else {
				nextImages = now.Add(backoff)
			}
			continue
		}
		backoff = 0
		a.adopt(resp.Config)
		if kind == wire.KindFull {
			if hostRetry {
				a.hostBackoff = nextBackoff(a.hostBackoff)
				nextFull = now.Add(a.hostBackoff)
			} else {
				a.hostBackoff = 0
				nextFull = now.Add(jittered(a.reportInterval(), a.cfg.JitterPercent, a.o.Jitter))
			}
		}
		nextImages = now.Add(jittered(a.imageInterval(), a.cfg.JitterPercent, a.o.Jitter))
		if resp.Applied && sent.Images != nil {
			a.acceptedHash, a.accepted = imagesHash(sent.Images), true
		}
		for _, w := range resp.Work {
			if ctx.Err() != nil {
				return
			}
			a.runJob(ctx, w)
		}
	}
}

// sleepUntil waits until t by the agent's clock; false when ctx ended first.
func (a *agent) sleepUntil(ctx context.Context, t time.Time) bool {
	d := t.Sub(a.o.Now())
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// send builds one report of kind and posts it. It returns the report as sent and, for a full report, whether
// the host part failed for a reason worth retrying soon.
func (a *agent) send(ctx context.Context, kind string) (wire.ReportResponse, wire.Report, bool, error) {
	a.seq++
	r := wire.Report{
		Node: a.o.NodeName, AgentVersion: version.Version, BootID: a.bootID, StartedAt: a.started, Seq: a.seq,
		Kind: kind, CollectedAt: a.o.Now(), KernelRelease: a.kernel, Arch: runtime.GOARCH,
	}
	hostRetry := false
	if kind == wire.KindFull {
		fctx, cancel := context.WithTimeout(ctx, fullReportTimeout)
		defer cancel()
		stop := a.keepAlive(fctx)
		defer stop()
		ctx = fctx
		var problems []wire.Problem
		r.Host, problems, hostRetry = a.collectHost(ctx)
		r.Images, r.Problems = a.scanImages(ctx)
		r.Problems = append(problems, r.Problems...)
		if r.Host != nil && a.cfg.MaxReportBytes > 0 {
			body, err := encodeReport(r)
			if err != nil {
				return wire.ReportResponse{}, r, false, err
			}
			if body.size() > a.cfg.MaxReportBytes {
				r.Problems = append(r.Problems, wire.Problem{Code: wire.ProblemCatalog,
					Detail: fmt.Sprintf("host SBOM of %d bytes exceeds the report limit %d", len(r.Host.SyftJSON), a.cfg.MaxReportBytes)})
				r.Host = nil
			}
		}
	} else if imgs, _ := a.scanImages(ctx); !a.accepted || imagesHash(imgs) != a.acceptedHash {
		r.Images = imgs
	}
	resp, err := a.client.Report(ctx, r)
	return resp, r, hostRetry, err
}

// collectHost stages the host inputs, has the cataloguer catalogue them and removes the stage. Host is nil when
// either step failed; retry is true when the failure is worth retrying before the next report interval.
func (a *agent) collectHost(ctx context.Context) (host *wire.Host, problems []wire.Problem, retry bool) {
	dir := filepath.Join(a.o.Scratch, fmt.Sprintf("host-%d", a.seq))
	in, err := StageHost(ctx, a.o.HostRoot, a.paths, dir, MaxHostBytes)
	if err != nil {
		a.o.Log.Error(err, "staging host inputs")
		return nil, []wire.Problem{{Code: wire.ProblemScratch, Detail: "host inputs not staged: " + err.Error()}}, true
	}
	defer func() { _ = os.RemoveAll(dir) }()
	problems = in.Problems
	resp, err := a.cat.Catalog(ctx, sbom.CatalogRequest{Source: sbom.CatalogSourceHostDir, Path: dir, MaxBytes: MaxHostBytes,
		TimeoutSeconds: int(hostCatalogTimeout / time.Second)})
	_ = os.RemoveAll(dir)
	if err != nil {
		kind, msg := workErrorOf(err)
		a.o.Log.Error(err, "cataloguing host inputs", "kind", kind)
		return nil, append(problems, wire.Problem{Code: wire.ProblemCatalog, Detail: failureDetail(kind, msg)}),
			kind == sbom.KindBusy || kind == sbom.KindTimeout
	}
	return &wire.Host{PackageDB: in.PackageDB, Binaries: in.Binaries, SyftJSON: resp.SyftJSON}, problems, false
}

// workErrorOf returns the kind and message of a cataloguer error. An error that is not a WorkError (the job's
// context ended) is a timeout.
func workErrorOf(err error) (string, string) {
	var we *catalog.WorkError
	if errors.As(err, &we) {
		return we.Kind, we.Msg
	}
	return sbom.KindTimeout, err.Error()
}

// failureDetail formats a cataloguer failure for a catalog problem or an SBOM result's Failure.
func failureDetail(kind, msg string) string { return kind + ": " + msg }

// scanImages lists the content store. Images is never nil; ContentStore is false when it could not be read.
func (a *agent) scanImages(ctx context.Context) (*wire.Images, []wire.Problem) {
	if a.store == nil {
		return &wire.Images{}, []wire.Problem{{Code: wire.ProblemContentStore, Detail: "no containerd content store (CRI-O)"}}
	}
	imgs, err := a.store.Scan(ctx)
	switch {
	case err == nil:
		return &wire.Images{ContentStore: true, Digests: imgs}, nil
	case errors.Is(err, fs.ErrNotExist):
		return &wire.Images{}, []wire.Problem{{Code: wire.ProblemContentStore, Path: a.storeHost,
			Detail: "no containerd content store at " + a.storeHost}}
	case errors.Is(err, fs.ErrPermission):
		return &wire.Images{}, []wire.Problem{{Code: wire.ProblemPermissionDenied, Path: a.storeHost, Detail: "permission denied"}}
	}
	a.o.Log.Error(err, "scanning the content store")
	return &wire.Images{}, []wire.Problem{{Code: wire.ProblemContentStore, Path: a.storeHost, Detail: err.Error()}}
}

// imagesHash identifies a cached-image list for change detection.
func imagesHash(imgs *wire.Images) [sha256.Size]byte {
	b, _ := json.Marshal(imgs) //nolint:errchkjson // plain struct of strings, bools and ints
	return sha256.Sum256(b)
}

// nextBackoff doubles the failed-report backoff from backoffBase up to maxBackoff.
func nextBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return backoffBase
	}
	return min(2*d, maxBackoff)
}

// jittered spreads d by ±pct percent with r drawing from [0, max].
func jittered(d time.Duration, pct int, r func(max time.Duration) time.Duration) time.Duration {
	spread := d * time.Duration(pct) / 100
	return d - spread + r(2*spread)
}
