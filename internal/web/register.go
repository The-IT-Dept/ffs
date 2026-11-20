package web

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/live"
	"github.com/the-it-dept/ffs/internal/web/ui"
)

// Register adds the HTTP server and the live-update hub to m, and subscribes the hub to the
// engine's changes. Neither is leader-only: they only read the store.
func Register(m manager.Manager, d deps.Deps) error {
	srv := apiserver.New(apiserver.Options{
		Store: d.Store, Config: d.Config, Feeds: feedInfos(d.Feeds.StaleAfter()), EOL: d.EOL,
		Kube: m.GetClient(), Pods: d.Inventory, Now: time.Now, Log: d.Log.WithName("api"),
	})
	hub := live.NewHub(live.Options{Store: d.Store, Marks: d.Store, Nodes: live.StoreNodeMarks(d.Store, d.Config.NodeAgent.StaleAfter, time.Now),
		Log: d.Log.WithName("live"), Cluster: d.Config.ClusterName})
	if err := m.Add(hub); err != nil {
		return fmt.Errorf("add live hub: %w", err)
	}
	d.Engine.AddObserver(hub)
	h := Handlers{API: srv.Handler(), Stream: hub, UI: ui.Handler(ui.Dist())}
	if err := m.Add(NewServer(d.Config, h, hub.Close)); err != nil {
		return fmt.Errorf("add web server: %w", err)
	}
	return nil
}

// feedInfos turns the runner's thresholds into a list sorted by feed name.
func feedInfos(staleAfter map[string]time.Duration) []apiserver.FeedInfo {
	out := make([]apiserver.FeedInfo, 0, len(staleAfter))
	for _, name := range slices.Sorted(maps.Keys(staleAfter)) {
		out = append(out, apiserver.FeedInfo{Name: name, StaleAfter: staleAfter[name]})
	}
	return out
}
