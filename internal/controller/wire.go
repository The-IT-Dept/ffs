package controller

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/exposure"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/feeds/cvelist"
	eolfeed "github.com/the-it-dept/ffs/internal/feeds/eol"
	"github.com/the-it-dept/ffs/internal/feeds/epss"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/kev"
	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/grype"
	"github.com/the-it-dept/ffs/internal/match/k8s"
	"github.com/the-it-dept/ffs/internal/match/osvfast"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/version"
)

// socketPoll is how often the acquirer re-dials the cataloguer socket before it starts.
const socketPoll = 2 * time.Second

// acquireSlack is how much longer than the cataloguer's own job timeout one acquisition may take: the
// registry budget wait, credential resolution and the response.
const acquireSlack = 5 * time.Minute

// wire builds the Phase 1 components, adds the leader-only ones to m and returns d with Registry,
// Engine, Acquirer, Feeds, EOL and Ready filled in. d must carry Config, Namespace, Store, Hooks and Log.
func wire(ctx context.Context, m manager.Manager, rc *rest.Config, d deps.Deps) (deps.Deps, error) {
	cfg, st, log := d.Config, d.Store, d.Log

	// The typed clientset makes uncached Gets, which is all the get-only Secret RBAC allows.
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return d, fmt.Errorf("kubernetes client: %w", err)
	}
	reg := registry.New(registry.Options{Kube: kube, Namespace: d.Namespace, Config: cfg.Registry, UserAgent: version.UserAgent()})

	grypeMatcher := grype.New(st)
	osvMatcher, upstreamMatcher, k8sMatcher := osvfast.New(st), upstream.New(st), k8s.New(st)
	eng := engine.New(engine.Options{
		Config: cfg, Store: st, Exceptions: st, Grype: grypeMatcher,
		Matchers: []match.Matcher{osvMatcher, upstreamMatcher, k8sMatcher},
		Records:  []match.RecordMatcher{osvMatcher, upstreamMatcher, k8sMatcher},
		CNA:      upstreamMatcher,
		Log:      log.WithName("engine"),
	})

	sources, fallback := sbom.DefaultSources(reg, cfg.Catalog)
	acq := sbom.NewAcquirer(sbom.AcquirerOptions{
		Store:        st,
		Sources:      sources,
		Fallback:     fallback,
		Concurrency:  cfg.Catalog.Concurrency,
		OnCatalogued: eng.OnImageCatalogued,
		JobTimeout:   cfg.Catalog.Timeout + acquireSlack,
		Log:          log.WithName("sbom"),
	})

	res := exposure.New(m.GetClient(), cfg.Exposure)
	inv := inventory.New(inventory.Options{
		Client: m.GetClient(), Version: kube.Discovery(), Store: st,
		Normalizer: inventory.NewNormalizer(reg, st, time.Now), Resolver: reg,
		Context: res, Hooks: eng, Acquirer: acq, ClusterName: cfg.ClusterName,
	})
	if err := res.Register(ctx, m, inv.MarkNamespace); err != nil {
		return d, err
	}
	if err := inv.Register(ctx, m); err != nil {
		return d, err
	}

	ev := eol.New(st, time.Now)
	if err := ev.Reload(ctx); err != nil {
		log.Error(err, "loading the stored end-of-life cycles failed; end-of-life checks wait for the next feed update")
	}
	fs, grypeFeed := newFeeds(cfg, st, eng, ev)
	var runner *feeds.Runner
	runner = feeds.NewRunner(st, fs, feeds.RunnerOptions{OnStale: func(_ context.Context, f string, last time.Time) {
		d.Hooks.FeedStale(f, last, runner.StaleAfter()[f])
	}})
	mc := metrics.NewCollector(st, metrics.CollectorOptions{FeedStaleAfter: runner.StaleAfter()})
	if err := metrics.Register(ctrlmetrics.Registry, mc); err != nil {
		return d, err
	}
	if err := m.Add(mc); err != nil {
		return d, fmt.Errorf("add metrics collector: %w", err)
	}
	if grypeFeed != nil {
		// Load the installed DB now, before anything matches, so a restart never waits for the next build.
		loadGrypeDB(ctx, grypeFeed, grypeMatcher, log)
	}

	sock := cfg.Catalog.Socket
	acquire := manager.RunnableFunc(func(ctx context.Context) error {
		if !waitForSocket(ctx, sock, socketPoll) {
			return nil
		}
		return acq.Start(ctx)
	})
	// Plain Runnables: each writes to the store, so each runs on the leader only.
	for _, r := range []manager.Runnable{inv, eng, acquire, manager.RunnableFunc(runner.Run)} {
		if err := m.Add(r); err != nil {
			return d, fmt.Errorf("add runnable: %w", err)
		}
	}

	d.Registry, d.Engine, d.Acquirer, d.Feeds, d.EOL = reg, eng, acq, runner, ev
	d.Ready = newReady(readyOptions{Synced: inv.Synced, Stats: acq.Stats, Idle: eng.Idle,
		GrypeOK: grypeReady(cfg.Feeds.GrypeDB.Enabled, st, log), Wait: readyWait, Log: log.WithName("ready")})
	return d, nil
}

// newFeeds builds the enabled feeds, sharing one HTTP client, each handing its output to eng. The
// grypedb feed is also returned on its own, nil when disabled.
func newFeeds(cfg config.Config, st *store.Store, eng *engine.Engine, ev *eol.Evaluator) (fs []feeds.Feed, grypeFeed *grypedb.Feed) {
	hc := feeds.NewHTTPClient(version.UserAgent())
	if c := cfg.Feeds.GrypeDB; c.Enabled {
		grypeFeed = grypedb.New(grypedb.Options{Config: c, DataDir: cfg.DataDir, Store: st, HTTP: hc, Handler: eng.OnGrypeDB})
		fs = append(fs, grypeFeed)
	}
	if c := cfg.Feeds.OSV; c.Enabled {
		fs = append(fs, osv.New(osv.Options{Config: c, Store: st, HTTP: hc, Handler: eng.OnOSVRecords,
			DataDir: cfg.DataDir, GitRepos: osvGitRepos(), Chainguard: cfg.Feeds.ChainguardOSV.Enabled}))
	}
	if c := cfg.Feeds.CVEList; c.Enabled {
		fs = append(fs, cvelist.New(cvelist.Options{Config: c, Store: st, HTTP: hc, Handler: eng.OnCNARecords}))
	}
	// KEV and EPSS also observe the engine: a new match takes its KEV date and EPSS score from the
	// last data applied before its findings are first built, not at the next sync.
	if c := cfg.Feeds.KEV; c.Enabled {
		f := kev.New(kev.Options{Config: c, Store: st, HTTP: hc, Handler: eng.OnAdvisoriesEnriched, DataDir: cfg.DataDir})
		eng.AddObserver(f)
		fs = append(fs, f)
	}
	if c := cfg.Feeds.EPSS; c.Enabled {
		f := epss.New(epss.Options{Config: c, Store: st, HTTP: hc, Handler: eng.OnAdvisoriesEnriched,
			DataDir: cfg.DataDir, Thresholds: []float64{cfg.Priority.EPSSBump, cfg.Priority.EPSSHigh}})
		eng.AddObserver(f)
		fs = append(fs, f)
	}
	if c := cfg.Feeds.EOL; c.Enabled {
		fs = append(fs, eolfeed.New(c, st, hc, ev.Reload))
	}
	return fs, grypeFeed
}

// osvGitRepos are the repositories whose OSV GIT records the osv feed keeps: the upstream-runtime
// map's and Kubernetes'.
func osvGitRepos() []string { return append(upstream.Repos(), k8s.Repo) }

// loadGrypeDB loads the installed Grype DB, if there is one, into the matcher. A failure is logged:
// the matcher then waits for the next build the feed installs.
func loadGrypeDB(ctx context.Context, f *grypedb.Feed, gm *grype.Matcher, log logr.Logger) {
	path, built, ok, err := f.Current(ctx)
	if err != nil {
		log.Error(err, "reading the installed Grype DB failed; matching waits for the next build")
		return
	}
	if !ok {
		return
	}
	if err := gm.Load(path, built); err != nil {
		log.Error(err, "loading the installed Grype DB failed; matching waits for the next build", "path", path)
	}
}

// feedStater reads a feed's recorded state (*store.Store).
type feedStater interface {
	FeedState(ctx context.Context, name string) (store.FeedState, error)
}

// grypeReady reports whether the Grype DB condition of readiness holds: the grypedb feed is
// disabled, or it has synced at least once. A store error is logged and counts as not yet.
func grypeReady(enabled bool, st feedStater, log logr.Logger) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		if !enabled {
			return true
		}
		fs, err := st.FeedState(ctx, feeds.NameGrypeDB)
		if err != nil {
			if ctx.Err() == nil {
				log.Error(err, "reading the Grype DB feed state for notification readiness failed")
			}
			return false
		}
		return !fs.LastSuccess.IsZero()
	}
}

// readyWait bounds how long notifications wait, once the inventory has synced, for the initial
// catalogue and match (the cataloguing queue, the engine and the first Grype DB sync). After it
// they start with what is matched so far, and the reason is logged: a Grype DB that cannot be
// downloaded, or work that never drains, must not hold back every alert for good.
const readyWait = time.Hour

// readyOptions are the conditions of Deps.Ready and the bound on waiting for them.
type readyOptions struct {
	Synced  func() bool
	Stats   func() sbom.AcquirerStats
	Idle    func() bool
	GrypeOK func(ctx context.Context) bool
	Wait    time.Duration
	Now     func() time.Time // time.Now when nil
	Log     logr.Logger
}

// newReady returns the sticky readiness of Deps.Ready. It never holds before the inventory has
// synced. After that it holds, for good, once the acquirer has nothing queued or in flight, the
// engine is idle and GrypeOK holds, or once Wait has passed since the inventory was first seen
// synced, whichever comes first.
func newReady(o readyOptions) func(ctx context.Context) bool {
	if o.Now == nil {
		o.Now = time.Now
	}
	var (
		ready atomic.Bool
		mu    sync.Mutex
		since time.Time // when the inventory was first seen synced
	)
	return func(ctx context.Context) bool {
		if ready.Load() {
			return true
		}
		if !o.Synced() {
			return false
		}
		pending := o.pending(ctx)
		mu.Lock()
		defer mu.Unlock()
		if ready.Load() {
			return true
		}
		now := o.Now()
		if since.IsZero() {
			since = now
		}
		switch {
		case len(pending) == 0:
			o.Log.Info("initial catalogue and match finished; notifications start")
		case now.Sub(since) >= o.Wait:
			o.Log.Info("notifications start before the initial catalogue and match finished",
				"waited", o.Wait.String(), "waitingFor", pending)
		default:
			return false
		}
		ready.Store(true)
		return true
	}
}

// pending names the conditions of readiness that do not hold yet, besides the inventory sync.
func (o readyOptions) pending(ctx context.Context) []string {
	var out []string
	if s := o.Stats(); s.Queued != 0 || s.InFlight != 0 {
		out = append(out, fmt.Sprintf("image cataloguing (%d queued, %d in progress)", s.Queued, s.InFlight))
	}
	if !o.Idle() {
		out = append(out, "finding recompute")
	}
	if !o.GrypeOK(ctx) {
		out = append(out, "first Grype DB sync")
	}
	return out
}
