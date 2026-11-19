package web

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/web/api"
)

// Register adds the HTTP server to m. It is not leader-only: it only reads the store.
func Register(m manager.Manager, d deps.Deps) error {
	svc := api.NewService(api.Options{
		Store: d.Store, Config: d.Config, Feeds: feedInfos(d.Feeds.StaleAfter()), EOL: d.EOL,
		Kube: m.GetClient(), Now: time.Now, Log: d.Log.WithName("api"),
	})
	if err := m.Add(NewServer(d.Config, api.NewHandler(svc), nil)); err != nil {
		return fmt.Errorf("add web server: %w", err)
	}
	return nil
}

// feedInfos turns the runner's thresholds into a list sorted by feed name.
func feedInfos(staleAfter map[string]time.Duration) []api.FeedInfo {
	out := make([]api.FeedInfo, 0, len(staleAfter))
	for _, name := range slices.Sorted(maps.Keys(staleAfter)) {
		out = append(out, api.FeedInfo{Name: name, StaleAfter: staleAfter[name]})
	}
	return out
}
