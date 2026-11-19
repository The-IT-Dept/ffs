package notify

import (
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/controller/deps"
)

// Register adds the notification Engine and the AlertTarget reconciler to m. newSink builds sinks;
// it is passed in because the sinks package imports this one.
func Register(m manager.Manager, d deps.Deps, newSink SinkFactory) error {
	e := New(d.Store, Options{
		Cluster: d.Config.ClusterName, DashboardURL: d.Config.DashboardURL, Ready: d.Ready,
		Changed: d.Engine.Changed(), FeedStaleAfter: d.Feeds.StaleAfter(), Retention: d.Config.Retention.Resolved,
	})
	if err := m.Add(e); err != nil {
		return err
	}
	r := &TargetReconciler{Client: m.GetClient(), Secrets: m.GetAPIReader(), Engine: e,
		Namespace: d.Namespace, Cluster: d.Config.ClusterName, NewSink: newSink}
	return r.SetupWithManager(m)
}
