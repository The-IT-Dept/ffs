package events

import (
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/controller/deps"
)

// Register adds the leader-only Event emitter to m and subscribes it to stale-feed signals.
func Register(m manager.Manager, d deps.Deps) error {
	em := New(Options{Store: d.Store, Recorder: d.Recorder, Config: d.Config.Events, Self: d.Self,
		Changed: d.Engine.Changed(), Log: d.Log.WithName("events")})
	if err := m.Add(em); err != nil {
		return err
	}
	d.Hooks.OnFeedStale(em.FeedStale)
	return nil
}
