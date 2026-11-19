package crds

import (
	"context"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/controller/deps"
)

// Register adds the Finding and Vulnerability writer, the Exception reconciler and the one-off
// startup prune of cached Exception rules to m. All three run on the leader only.
func Register(m manager.Manager, d deps.Deps) error {
	w := NewWriter(WriterOptions{Client: m.GetClient(), Store: d.Store, Config: d.Config, Namespace: d.Namespace,
		Self: d.Self, Recorder: d.Recorder, Changed: d.Engine.Changed()})
	if err := m.Add(w); err != nil {
		return err
	}
	r := &ExceptionReconciler{Client: m.GetClient(), Store: d.Store, Engine: d.Engine, Config: d.Config,
		Namespace: d.Namespace, Now: time.Now}
	if err := r.SetupWithManager(m); err != nil {
		return err
	}
	log := d.Log.WithName("crds")
	// A failed prune leaves orphaned rules cached until the next start; it is not worth stopping for.
	return m.Add(manager.RunnableFunc(func(ctx context.Context) error {
		if err := r.PruneCache(ctx); err != nil && ctx.Err() == nil {
			log.Error(err, "pruning cached Exception rules failed")
		}
		return nil
	}))
}
