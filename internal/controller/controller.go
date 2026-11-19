// Package controller wires every ffs component into a controller-runtime manager and runs it: a
// single replica behind leader election, with the store-writing components on the leader only.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
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
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/store"
)

// leaderElectionID names the leader-election Lease.
const leaderElectionID = "ffs.theitdept.au"

// Options configures Run.
type Options struct {
	Config      config.Config
	LeaderElect bool   // default true
	MetricsAddr string // default ":8443"; "0" disables
	ProbeAddr   string // default ":8081"; "0" disables
	Namespace   string // tests only: overrides Config.Namespace
}

// NewScheme returns the scheme the manager uses: the client-go types, the ffs API and the Gateway
// API types exposure reads.
func NewScheme() (*runtime.Scheme, error) {
	s := runtime.NewScheme()
	if err := errors.Join(clientgoscheme.AddToScheme(s), v1alpha1.AddToScheme(s), exposure.AddToScheme(s)); err != nil {
		return nil, fmt.Errorf("build scheme: %w", err)
	}
	return s, nil
}

// managerOptions returns the manager options for install namespace ns, without the scheme.
func managerOptions(o Options, ns string) manager.Options {
	return manager.Options{
		LeaderElection:                o.LeaderElect,
		LeaderElectionID:              leaderElectionID,
		LeaderElectionNamespace:       ns,
		LeaderElectionReleaseOnCancel: true,
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
}

// Run builds the manager, wires every component into it and runs it until ctx is done. The store
// is closed after the manager has stopped.
func Run(ctx context.Context, rc *rest.Config, o Options) (err error) {
	cfg := o.Config
	ns := o.Namespace
	if ns == "" {
		ns = cfg.Namespace
	}
	log := logf.Log

	st, err := store.Open(ctx, cfg.StorePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() {
		if cerr := st.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close store: %w", cerr))
		}
	}()

	scheme, err := NewScheme()
	if err != nil {
		return err
	}
	mo := managerOptions(o, ns)
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
	for _, r := range registrars {
		if err := r(m, d); err != nil {
			return err
		}
	}

	if err := m.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	sock := cfg.Catalog.Socket
	if err := m.AddReadyzCheck("catalog", func(req *http.Request) error { return dialSocket(req.Context(), sock) }); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}

	return m.Start(ctx)
}
