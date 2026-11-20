package agent

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
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
	// configTimeout bounds the config probe that precedes each full report.
	configTimeout = 10 * time.Second
	// catalogClientTimeout bounds one cataloguer call; each job is bounded by its own deadline first.
	catalogClientTimeout = 31 * time.Minute
	// hostCatalogTimeout is the cataloguer's limit for the host SBOM.
	hostCatalogTimeout = 10 * time.Minute
	// fullReportTimeout bounds building and sending one full report.
	fullReportTimeout = 25 * time.Minute
	// imagesReportTimeout bounds scanning the content store and sending one images report.
	imagesReportTimeout = clientTimeout + time.Minute
	// maxBackoff caps the failed-report backoff.
	maxBackoff = 5 * time.Minute
	// backoffJitterPercent spreads each backoff, and each wait for a Retry-After, so nodes that failed together do
	// not retry together.
	backoffJitterPercent = 20
	// unappliedLogEvery is how many reports in a row the controller leaves unapplied before the agent says so.
	unappliedLogEvery = 3
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
	instance     string // random per process: orders this process's reports after any earlier one's
	kernel       string
	started      time.Time
	cfg          wire.AgentConfig
	seq          uint64
	acceptedHash [sha256.Size]byte // hash of the last Images the controller applied
	accepted     bool
	host         *hostInventory // the last host inventory collected, until the controller stores a host part
	lastContact  time.Time      // when the controller last answered
	unapplied    int            // reports in a row the controller did not apply
	pulse        pulse
}

// hostInventory is a collected host inventory: what staging found and the host SBOM in a scratch file. It is
// kept until the controller has stored a host part, so a full report that failed is resent without staging and
// cataloguing the host again.
type hostInventory struct {
	packageDB string
	binaries  []wire.Binary
	problems  []wire.Problem
	sbom      sbomFile
	collected time.Time
}

// schedule is when each kind of report is next due and how far each has backed off. The two backoffs are
// separate: images reports that succeed never cut short the backoff of failing full reports.
type schedule struct {
	nextFull, nextImages       time.Time
	fullBackoff, imagesBackoff time.Duration
}

// Run sends reports until ctx ends: a full report at start (after up to 30s of jitter) and then every
// report interval, an images report every image-list interval, and the work the controller hands back.
func Run(ctx context.Context, o Options) error {
	a, err := newAgent(o)
	if err != nil {
		return err
	}
	a.loop(ctx)
	return nil
}

func newAgent(o Options) (*agent, error) {
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
	a := &agent{o: o, client: client, cat: catalog.NewSocketClient(o.CatalogSocket, catalogClientTimeout), started: o.Now(),
		instance: newInstance(), cfg: fallbackConfig}
	a.lastContact = a.started
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
	return a, nil
}

// newInstance is 32 random hex characters.
func newInstance() string {
	b := make([]byte, 16)
	_, _ = crand.Read(b) // never fails
	return hex.EncodeToString(b)
}

// cleanScratch creates the scratch dir, readable by the non-root cataloguer whatever the umask, and removes the
// stage dirs and spooled SBOMs a previous run left.
func (a *agent) cleanScratch() error {
	if err := os.MkdirAll(a.o.Scratch, 0o755); err != nil { //nolint:gosec // G301: the non-root cataloguer reads staged files
		return err
	}
	// MkdirAll's mode is filtered by the umask and leaves an existing dir as it is.
	if err := os.Chmod(a.o.Scratch, 0o755); err != nil { //nolint:gosec // G302: the non-root cataloguer reads staged files
		return err
	}
	entries, err := os.ReadDir(a.o.Scratch)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, "host-") || strings.HasPrefix(n, "work-") || strings.HasPrefix(n, "sbom-") {
			if err := os.RemoveAll(filepath.Join(a.o.Scratch, n)); err != nil {
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
	stop := a.startPulse()
	defer stop()
	defer a.dropHost()
	s := &schedule{nextFull: a.o.Now().Add(a.o.Jitter(startJitter))}
	s.nextImages = s.nextFull.Add(jittered(a.imageInterval(), a.cfg.JitterPercent, a.o.Jitter))
	for {
		due := s.nextImages
		if !s.nextFull.After(due) {
			due = s.nextFull
		}
		a.lease(due.Sub(a.o.Now()))
		if !a.sleepUntil(ctx, due) {
			return
		}
		var work []wire.WorkRequest
		if !a.o.Now().Before(s.nextFull) {
			work = a.fullReport(ctx, s)
		} else {
			work = a.imagesReport(ctx, s)
		}
		for len(work) > 0 && ctx.Err() == nil {
			w := work[0]
			work = work[1:]
			a.runJob(ctx, w)
			// A job can outlast the image-list interval: report between jobs, so the node does not look stale.
			if ctx.Err() == nil && !a.o.Now().Before(s.nextImages) {
				work = append(work, a.imagesReport(ctx, s)...)
			}
		}
		if ctx.Err() != nil {
			return
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

// newReport starts the next report of kind.
func (a *agent) newReport(kind string) wire.Report {
	a.seq++
	return wire.Report{
		Node: a.o.NodeName, AgentVersion: version.Version, BootID: a.bootID, Instance: a.instance, StartedAt: a.started,
		Seq: a.seq, Kind: kind, CollectedAt: a.o.Now(), KernelRelease: a.kernel, Arch: runtime.GOARCH,
	}
}

// fullReport sends a full report and schedules the next reports; it returns the work the controller handed back.
// It first probes the controller's config, and skips the report when the controller does not answer. The host
// inventory is the one kept from an earlier attempt while that is younger than the report interval, so retries
// never stage or catalogue the host again; it is dropped once the controller has stored a host part.
func (a *agent) fullReport(parent context.Context, s *schedule) []wire.WorkRequest {
	a.lease(fullReportTimeout)
	ctx, cancel := context.WithTimeout(parent, fullReportTimeout)
	defer cancel()
	if err := a.probe(ctx); err != nil {
		if parent.Err() != nil {
			return nil
		}
		wait := a.retryIn(err, &s.fullBackoff)
		s.nextFull = a.o.Now().Add(wait)
		a.logFailure(err, "the controller did not answer; the full report waits", "retryIn", wait)
		return nil
	}
	if next := a.o.Now().Add(jittered(a.imageInterval(), a.cfg.JitterPercent, a.o.Jitter)); next.Before(s.nextImages) {
		s.nextImages = next // the controller's image-list interval is shorter than the one assumed so far
	}
	inv, problems, retry := a.hostInventory(ctx)
	r := a.newReport(wire.KindFull)
	var imageProblems []wire.Problem
	r.Images, imageProblems = a.scanImages(ctx)
	r.Problems = append(problems, imageProblems...)
	var doc *sbomFile
	if inv != nil {
		r.Host = &wire.Host{PackageDB: inv.packageDB, Binaries: inv.binaries}
		r.Problems = append(slices.Clone(inv.problems), r.Problems...)
		doc = &inv.sbom
		if body, err := encodeReport(r, doc); err == nil && a.cfg.MaxReportBytes > 0 && body.size() > a.cfg.MaxReportBytes {
			r.Problems = append(r.Problems, wire.Problem{Code: wire.ProblemCatalog,
				Detail: fmt.Sprintf("host SBOM of %d bytes exceeds the report limit %d", inv.sbom.size, a.cfg.MaxReportBytes)})
			r.Host, doc = nil, nil
			a.dropHost()
		}
	}
	resp, err := a.client.Report(ctx, r, doc)
	a.touch()
	if parent.Err() != nil {
		return nil
	}
	now := a.o.Now()
	if err != nil {
		wait := a.retryIn(err, &s.fullBackoff)
		s.nextFull = now.Add(wait)
		a.logFailure(err, "sending a full report", "seq", r.Seq, "retryIn", wait)
		return nil
	}
	a.answered(now, r, resp)
	if retry || (resp.HostRetry && r.Host != nil) {
		// The host part was not collected, or not stored: resend it soon, with the inventory kept.
		s.nextFull = now.Add(a.retryIn(nil, &s.fullBackoff))
	} else {
		// Stored; or, when the controller did not apply the report, not worth keeping past the report interval.
		a.dropHost()
		s.fullBackoff = 0
		s.nextFull = now.Add(jittered(a.reportInterval(), a.cfg.JitterPercent, a.o.Jitter))
	}
	s.imagesBackoff = 0
	s.nextImages = now.Add(jittered(a.imageInterval(), a.cfg.JitterPercent, a.o.Jitter))
	return resp.Work
}

// imagesReport sends an images report, with the cached images only when they changed since the last list the
// controller applied, and schedules the next one; it returns the work the controller handed back.
func (a *agent) imagesReport(parent context.Context, s *schedule) []wire.WorkRequest {
	a.lease(imagesReportTimeout)
	ctx, cancel := context.WithTimeout(parent, imagesReportTimeout)
	defer cancel()
	r := a.newReport(wire.KindImages)
	if imgs, _ := a.scanImages(ctx); imgs != nil && (!a.accepted || imagesHash(imgs) != a.acceptedHash) {
		r.Images = imgs
	}
	resp, err := a.client.Report(ctx, r, nil)
	a.touch()
	if parent.Err() != nil {
		return nil
	}
	now := a.o.Now()
	if err != nil {
		wait := a.retryIn(err, &s.imagesBackoff)
		s.nextImages = now.Add(wait)
		a.logFailure(err, "sending an images report", "seq", r.Seq, "retryIn", wait)
		return nil
	}
	a.answered(now, r, resp)
	s.imagesBackoff = 0
	s.nextImages = now.Add(jittered(a.imageInterval(), a.cfg.JitterPercent, a.o.Jitter))
	return resp.Work
}

// probe fetches the agent config: a cheap check that the controller is answering, before the host is staged and
// catalogued.
func (a *agent) probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, configTimeout)
	defer cancel()
	cfg, err := a.client.Config(ctx)
	if err != nil {
		return err
	}
	a.lastContact = a.o.Now()
	a.adopt(cfg)
	return nil
}

// answered records the controller's answer to r.
func (a *agent) answered(now time.Time, r wire.Report, resp wire.ReportResponse) {
	a.lastContact = now
	a.adopt(resp.Config)
	if resp.Applied && r.Images != nil {
		a.acceptedHash, a.accepted = imagesHash(r.Images), true
	}
	if resp.Applied {
		a.unapplied = 0
		return
	}
	a.unapplied++
	if a.unapplied%unappliedLogEvery == 0 {
		a.o.Log.Info("the controller has not applied this agent's last reports", "count", a.unapplied, "kind", r.Kind,
			"seq", r.Seq, "instance", a.instance)
	}
}

// retryIn is how long to wait before retrying after err: at least the controller's Retry-After when it answered
// 429 with one, and otherwise the next step of *backoff. Either is spread by backoffJitterPercent.
func (a *agent) retryIn(err error, backoff *time.Duration) time.Duration {
	var se *StatusError
	if errors.As(err, &se) && se.Code == http.StatusTooManyRequests && se.RetryAfter > 0 {
		return se.RetryAfter + a.o.Jitter(se.RetryAfter*backoffJitterPercent/100)
	}
	*backoff = nextBackoff(*backoff)
	return jittered(*backoff, backoffJitterPercent, a.o.Jitter)
}

// logFailure logs a failed exchange with the controller. While the controller is starting, restarting or
// shedding load (connection refused, 503, 429), it is logged at Info until a report interval has passed since
// the controller last answered; anything else is an error.
func (a *agent) logFailure(err error, msg string, kv ...any) {
	if controllerUnavailable(err) && a.o.Now().Sub(a.lastContact) < a.reportInterval() {
		a.o.Log.Info(msg, append(kv, "reason", err.Error())...)
		return
	}
	a.o.Log.Error(err, msg, kv...)
}

// controllerUnavailable reports whether err means the controller is not (yet) taking reports.
func controllerUnavailable(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code == http.StatusServiceUnavailable || se.Code == http.StatusTooManyRequests
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// hostInventory returns the kept host inventory while it is younger than the report interval, and otherwise
// collects a new one. retry is true when collection failed for a reason worth retrying before the next report
// interval.
func (a *agent) hostInventory(ctx context.Context) (inv *hostInventory, problems []wire.Problem, retry bool) {
	if a.host != nil && a.o.Now().Sub(a.host.collected) < a.reportInterval() {
		return a.host, nil, false
	}
	a.dropHost()
	return a.collectHost(ctx)
}

// dropHost removes the kept host inventory and its spooled SBOM.
func (a *agent) dropHost() {
	if a.host != nil {
		_ = os.Remove(a.host.sbom.path)
		a.host = nil
	}
}

// collectHost stages the host inputs, has the cataloguer catalogue them into a spooled SBOM and removes the stage.
// The inventory is nil when either step failed; retry is true when the failure is worth retrying before the
// next report interval.
func (a *agent) collectHost(ctx context.Context) (inv *hostInventory, problems []wire.Problem, retry bool) {
	n := a.seq + 1 // the seq of the report it is collected for
	dir := filepath.Join(a.o.Scratch, fmt.Sprintf("host-%d", n))
	in, err := StageHost(ctx, a.o.HostRoot, a.paths, dir, MaxHostBytes)
	if err != nil {
		a.o.Log.Error(err, "staging host inputs")
		return nil, []wire.Problem{{Code: wire.ProblemScratch, Detail: "host inputs not staged: " + err.Error()}}, true
	}
	defer func() { _ = os.RemoveAll(dir) }()
	doc, err := a.cat.Catalog(ctx, sbom.CatalogRequest{Source: sbom.CatalogSourceHostDir, Path: dir, MaxBytes: MaxHostBytes,
		TimeoutSeconds: int(hostCatalogTimeout / time.Second)}, filepath.Join(a.o.Scratch, fmt.Sprintf("sbom-host-%d.json", n)))
	_ = os.RemoveAll(dir)
	if err != nil {
		kind, msg := workErrorOf(err)
		a.o.Log.Error(err, "cataloguing host inputs", "kind", kind)
		return nil, append(in.Problems, wire.Problem{Code: wire.ProblemCatalog, Detail: failureDetail(kind, msg)}),
			kind == sbom.KindBusy || kind == sbom.KindTimeout
	}
	a.host = &hostInventory{packageDB: in.PackageDB, binaries: in.Binaries, problems: in.Problems,
		sbom: sbomFile{path: doc.Path, size: doc.Size}, collected: a.o.Now()}
	return a.host, nil, false
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

// scanImages lists the content store. Images is nil (unchanged since the last list) when an unexpected error
// stopped the scan, and has ContentStore false when there is no content store or it cannot be read.
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
	// Not a statement about the content store: the controller keeps the list it has.
	a.o.Log.Error(err, "scanning the content store")
	return nil, []wire.Problem{{Code: wire.ProblemContentStore, Path: a.storeHost, Detail: err.Error()}}
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
