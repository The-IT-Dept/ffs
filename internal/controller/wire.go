package controller

import (
	"context"
	"fmt"
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
	"github.com/the-it-dept/ffs/internal/exposure"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/feeds/cvelist"
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

// wire builds the Phase 1 components, adds the leader-only ones to m and returns d with Registry,
// Engine, Acquirer, Feeds and Ready filled in. d must carry Config, Namespace, Store, Hooks and Log.
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

	acq := sbom.NewAcquirer(sbom.AcquirerOptions{
		Store:        st,
		Sources:      []sbom.Source{sbom.NewAttestationSource(reg), sbom.NewCatalogSource(reg, cfg.Catalog)},
		Concurrency:  cfg.Catalog.Concurrency,
		OnCatalogued: eng.OnImageCatalogued,
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

	fs, grypeFeed := newFeeds(cfg, st, eng)
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

	d.Registry, d.Engine, d.Acquirer, d.Feeds = reg, eng, acq, runner
	d.Ready = newReady(inv.Synced, acq.Stats, eng.Idle, grypeReady(cfg.Feeds.GrypeDB.Enabled, st))
	return d, nil
}

// newFeeds builds the enabled feeds, sharing one HTTP client, each handing its output to eng. The
// grypedb feed is also returned on its own, nil when disabled.
func newFeeds(cfg config.Config, st *store.Store, eng *engine.Engine) (fs []feeds.Feed, grypeFeed *grypedb.Feed) {
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
	if c := cfg.Feeds.KEV; c.Enabled {
		fs = append(fs, kev.New(kev.Options{Config: c, Store: st, HTTP: hc, Handler: eng.OnAdvisoriesEnriched, DataDir: cfg.DataDir}))
	}
	if c := cfg.Feeds.EPSS; c.Enabled {
		fs = append(fs, epss.New(epss.Options{Config: c, Store: st, HTTP: hc, Handler: eng.OnAdvisoriesEnriched,
			DataDir: cfg.DataDir, Thresholds: []float64{cfg.Priority.EPSSBump, cfg.Priority.EPSSHigh}}))
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
// disabled, or it has synced at least once.
func grypeReady(enabled bool, st feedStater) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		if !enabled {
			return true
		}
		fs, err := st.FeedState(ctx, feeds.NameGrypeDB)
		return err == nil && !fs.LastSuccess.IsZero()
	}
}

// newReady returns the sticky readiness of Deps.Ready: once the inventory has synced, the acquirer
// has nothing queued or in flight, the engine is idle and grypeOK holds, it returns true for good.
func newReady(synced func() bool, stats func() sbom.AcquirerStats, idle func() bool, grypeOK func(ctx context.Context) bool) func(ctx context.Context) bool {
	var ready atomic.Bool
	return func(ctx context.Context) bool {
		if ready.Load() {
			return true
		}
		if !synced() {
			return false
		}
		if s := stats(); s.Queued != 0 || s.InFlight != 0 {
			return false
		}
		if !idle() || !grypeOK(ctx) {
			return false
		}
		ready.Store(true)
		return true
	}
}
