package web

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/ui"
)

// Register adds the HTTP server to m. It is not leader-only: it only reads the store.
func Register(m manager.Manager, d deps.Deps) error {
	srv := apiserver.New(apiserver.Options{
		Store: d.Store, Config: d.Config, Feeds: feedInfos(d.Feeds.StaleAfter()), EOL: d.EOL,
		Kube: m.GetClient(), Now: time.Now, Log: d.Log.WithName("api"),
	})
	if err := m.Add(NewServer(d.Config, Handlers{API: srv.Handler(), UI: ui.Handler(ui.Dist())}, nil)); err != nil {
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
