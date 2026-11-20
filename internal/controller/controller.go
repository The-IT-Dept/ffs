// Package controller wires every ffs component into a controller-runtime manager and runs it: a
// single replica behind leader election, with the store-writing components on the leader only.
package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	coordinationv1client "k8s.io/client-go/kubernetes/typed/coordination/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/exposure"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/version"
)

// leaderElectionID names the leader-election Lease.
const leaderElectionID = "ffs.theitdept.au"

// leaderRenewDeadline is controller-runtime's default renew deadline. The lease clients time out
// at half of it, as controller-runtime's own lock does, so one hung request cannot cost the lease.
const leaderRenewDeadline = 10 * time.Second

// Options configures Run.
type Options struct {
	Config      config.Config
	LeaderElect bool   // default true
	MetricsAddr string // default ":8443"; "0" disables
	ProbeAddr   string // default ":8081"; "0" disables
	// PprofAddr, when set, serves net/http/pprof on this loopback address for diagnosis; off by
	// default. It is not the manager's pprof server, which stays disabled.
	PprofAddr string
	Namespace string // tests only: overrides Config.Namespace
}

// NewScheme returns the scheme the manager uses: the client-go types, the ffs API and the Gateway
// API types exposure reads, and the OpenReports types.
func NewScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := errors.Join(clientgoscheme.AddToScheme(s), v1alpha1.AddToScheme(s), exposure.AddToScheme(s), orv1alpha1.Install(s)); err != nil {
		return nil, fmt.Errorf("build scheme: %w", err)
	}
	return s, nil
}

// managerOptions returns the manager options for install namespace ns, without the scheme. With
// leader election on, rc builds the Lease lock (see leaderLock).
func managerOptions(o Options, ns string, rc *rest.Config) (manager.Options, error) {
	mo := manager.Options{
		LeaderElection:                o.LeaderElect,
		LeaderElectionID:              leaderElectionID,
		LeaderElectionNamespace:       ns,
		LeaderElectionReleaseOnCancel: true,
		RenewDeadline:                 ptr.To(leaderRenewDeadline),
		HealthProbeBindAddress:        o.ProbeAddr,
		PprofBindAddress:              "0", // spec §7: no pprof or debug endpoints
		Metrics: metricsserver.Options{BindAddress: o.MetricsAddr, SecureServing: true,
			FilterProvider: filters.WithAuthenticationAndAuthorization},
		Cache: inventory.CacheOptions(),
		// A cached Secret Get would start a list/watch, which the get-only Secret RBAC forbids.
		Client:                  client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
		GracefulShutdownTimeout: ptr.To(30 * time.Second),
		// Runnables log through the logger in their context (logr.FromContextOrDiscard).
		BaseContext: func() context.Context { return logf.IntoContext(context.Background(), logf.Log) },
	}
	if o.LeaderElect {
		lock, err := leaderLock(rc, ns)
		if err != nil {
			return manager.Options{}, err
		}
		mo.LeaderElectionResourceLockInterface = lock
	}
	return mo, nil
}

// leaderLock builds the leader-election Lease lock the way controller-runtime does, except that it
// records no Events. controller-runtime's lock records core/v1 Events, which the chart's RBAC does
// not grant (spec §7 allows events.k8s.io only), so every lease change would log a "forbidden"
// error. LeaseLock.RecordEvent does nothing without an EventRecorder.
func leaderLock(rc *rest.Config, ns string) (resourcelock.Interface, error) {
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("leader election identity: %w", err)
	}
	c := rest.AddUserAgent(rest.CopyConfig(rc), "leader-election")
	c.Timeout = leaderRenewDeadline / 2
	core, err := corev1client.NewForConfig(c)
	if err != nil {
		return nil, fmt.Errorf("leader election client: %w", err)
	}
	coord, err := coordinationv1client.NewForConfig(c)
	if err != nil {
		return nil, fmt.Errorf("leader election client: %w", err)
	}
	return resourcelock.New(resourcelock.LeasesResourceLock, ns, leaderElectionID, core, coord,
		resourcelock.ResourceLockConfig{Identity: host + "_" + string(uuid.NewUUID())})
}

// resetCrashQuarantines lifts, once per new controller version and before anything acquires, what
// crashes of the previous version counted against images and node host inventories
// (Store.ResetCrashQuarantines), so a release that fixes a crash retries at once.
func resetCrashQuarantines(ctx context.Context, st *store.Store, ver string, log logr.Logger) error {
	r, changed, err := st.ResetCrashQuarantines(ctx, ver)
	if err != nil {
		return err
	}
	switch {
	case !changed:
	case r.Previous == "":
		log.Info("recorded controller version", "version", ver, "cleared", r.Cleared())
	default:
		log.Info("controller version changed; quarantines from crashes of the previous version cleared", "previous", r.Previous,
			"version", ver, "cleared", r.Cleared(), "images", r.Images, "agentJobs", r.Jobs, "inflight", r.Inflight,
			"attempts", r.Attempts, "matchRuns", r.Matches, "errors", r.Errors)
	}
	return nil
}

// Run builds the manager, wires every component into it and runs it until ctx is done. The store
// is closed after the manager's runnables have stopped (runManager).
func Run(ctx context.Context, rc *rest.Config, o Options) (err error) {
	cfg := o.Config
	ns := o.Namespace
	if ns == "" {
		ns = cfg.Namespace
	}
	log := logf.Log

	if o.PprofAddr != "" {
		stop, err := startPprof(ctx, o.PprofAddr, log)
		if err != nil {
			return err
		}
		defer stop()
	}

	// Before the first database is opened: the SQLite runtime reads the environment once.
	if _, err := grypedb.UseSQLiteTempDir(cfg.DataDir); err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.StorePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	// Until the manager starts nothing runs that uses the store, so a failure before then closes it here; from then
	// on runManager closes it, once the runnables have stopped.
	started := false
	defer func() {
		if !started {
			err = errors.Join(err, closeStore(st))
		}
	}()
	if err := resetCrashQuarantines(ctx, st, version.Version, log); err != nil {
		return err
	}

	scheme, err := NewScheme()
	if err != nil {
		return err
	}
	mo, err := managerOptions(o, ns, rc)
	if err != nil {
		return err
	}
	mo.Scheme = scheme
	m, err := manager.New(rc, mo)
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	self, err := FindSelf(ctx, m.GetAPIReader(), ns, cfg.DeploymentName)
	if err != nil {
		log.Info("cannot read the ffs Deployment; Events about ffs itself are not emitted", "error", err.Error())
	}

	d, err := wire(ctx, m, rc, deps.Deps{
		Config: cfg, Namespace: ns, Self: self, Store: st,
		Recorder: m.GetEventRecorder("ffs"), Hooks: &deps.Hooks{}, Log: log,
	})
	if err != nil {
		return err
	}
	if err := register(m, d, registrars); err != nil {
		return err
	}

	if err := m.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	sock := cfg.Catalog.Socket
	if err := m.AddReadyzCheck("catalog", func(req *http.Request) error { return dialSocket(req.Context(), sock) }); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}

	started = true
	return runManager(ctx, m, st, log)
}

// starter is the part of manager.Manager runManager uses.
type starter interface {
	Start(ctx context.Context) error
}

// runManager runs m until ctx is done, then closes st once every runnable has returned. Start returns before they all
// have only when they outlast the graceful shutdown timeout (its error then wraps context.DeadlineExceeded), and they
// may still be using the store: it is left open for them, since the process exits next and SQLite's journal keeps
// the database consistent. The pod's termination grace period leaves room for the timeout and the close (F117).
func runManager(ctx context.Context, m starter, st io.Closer, log logr.Logger) error {
	err := m.Start(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		log.Info("components did not stop within the graceful shutdown timeout; the store is left open for them", "error", err.Error())
		return err
	}
	return errors.Join(err, closeStore(st))
}

func closeStore(st io.Closer) error {
	if err := st.Close(); err != nil {
		return fmt.Errorf("close store: %w", err)
	}
	return nil
}
