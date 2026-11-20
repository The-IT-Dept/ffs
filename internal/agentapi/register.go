package agentapi

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/sbom"
)

// registerTarget is the part of the manager register uses.
type registerTarget interface {
	Add(manager.Runnable) error
	GetClient() client.Client
	GetFieldIndexer() client.FieldIndexer
}

// Register adds the node-group reconciler to m and, when the node agent is enabled, the agent API server
// with its report ingestion and work queue. Every runnable is leader-only.
func Register(m manager.Manager, d deps.Deps) error {
	return register(m, func(h toolscache.ResourceEventHandler) error {
		inf, err := m.GetCache().GetInformer(context.Background(), &corev1.Node{})
		if err != nil {
			return err
		}
		_, err = inf.AddEventHandler(h)
		return err
	}, d)
}

// register is Register with the Node informer's AddEventHandler as onNodes. Registrars run before the
// manager starts, so the pod index exists before the cache starts. The reconciler always runs: with the
// agent disabled it switches the runtime owner back and drops agent membership.
func register(m registerTarget, onNodes func(toolscache.ResourceEventHandler) error, d deps.Deps) error {
	if err := IndexPods(context.Background(), m.GetFieldIndexer()); err != nil {
		return fmt.Errorf("agent API: pod index: %w", err)
	}
	pods := NewPodIndex(m.GetClient())
	log := d.Log.WithName("nodeagent")
	opts := ReconcilerOptions{Store: d.Store, Engine: d.Engine, Nodes: m.GetClient(), Pods: pods, Config: d.Config, Log: log}
	if d.Inventory != nil {
		opts.Inventory = d.Inventory
	}
	rec := NewReconciler(opts)
	if err := onNodes(nodeEvents(rec.Trigger)); err != nil {
		return fmt.Errorf("agent API: node events: %w", err)
	}
	if err := m.Add(rec); err != nil {
		return fmt.Errorf("agent API: add reconciler: %w", err)
	}
	na := d.Config.NodeAgent
	if !na.Enabled {
		return nil
	}
	work := NewWorkQueue(WorkOptions{Store: d.Store, Acquirer: d.Acquirer, Pods: pods, PerReport: na.WorkPerReport,
		Timeout: na.WorkTimeout, Log: log})
	ing := NewIngester(IngesterOptions{Store: d.Store, Acquirer: d.Acquirer, Nodes: NewNodeReader(m.GetClient()), Work: work,
		Trigger: rec.Trigger, Config: na, Log: log})
	auth := NewTokenReviewAuthenticator(m.GetClient(), m.GetClient(), AuthOptions{Namespace: na.Namespace, ServiceAccount: na.ServiceAccount})
	srv := NewServer(ServerOptions{Listen: na.Listen, CertDir: na.CertDir, MaxReportBytes: na.MaxReportBytes,
		MaxSBOMBytes: sbom.MaxSBOMBytes + 1<<20, Auth: auth, Reports: ing, SBOMs: work,
		Config: func() wire.AgentConfig { return WireConfig(na) }, Log: log})
	if err := m.Add(srv); err != nil {
		return fmt.Errorf("agent API: add server: %w", err)
	}
	return nil
}
