package openreports

import (
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/controller/deps"
)

// Register adds the leader-only OpenReports writer to m.
func Register(m manager.Manager, d deps.Deps) error {
	w := New(m.GetClient(), m.GetAPIReader(), discovery.NewDiscoveryClientForConfigOrDie(m.GetConfig()), d.Store,
		d.Config.OpenReports, Options{Namespace: d.Namespace, Changed: d.Engine.Changed()})
	return m.Add(w)
}
