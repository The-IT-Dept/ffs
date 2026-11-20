// Package deps holds what the controller hands to each output package's Register function. Output
// packages import it; it imports none of them.
package deps

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

// FeedStaleFunc is told that a feed has gone stale: its last success (zero when it never synced)
// is more than staleAfter ago.
type FeedStaleFunc func(feed string, lastSuccess time.Time, staleAfter time.Duration)

// Hooks fans controller-level signals out to the output packages that subscribe. The zero value
// is ready to use and it is safe for concurrent use.
type Hooks struct {
	mu        sync.Mutex
	feedStale []FeedStaleFunc
}

// OnFeedStale subscribes f to FeedStale.
func (h *Hooks) OnFeedStale(f FeedStaleFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.feedStale = append(h.feedStale, f)
}

// FeedStale calls every FeedStale subscriber, in subscription order.
func (h *Hooks) FeedStale(feed string, lastSuccess time.Time, staleAfter time.Duration) {
	h.mu.Lock()
	subs := slices.Clone(h.feedStale)
	h.mu.Unlock()
	for _, f := range subs {
		f(feed, lastSuccess, staleAfter)
	}
}

// Deps is what every Registrar receives.
type Deps struct {
	Config    config.Config
	Namespace string                  // ffs install namespace
	Self      *corev1.ObjectReference // ffs Deployment; nil when not found
	Store     *store.Store
	Engine    *engine.Engine
	Registry  *registry.Client
	Acquirer  *sbom.Acquirer
	Feeds     *feeds.Runner
	EOL       *eol.Evaluator
	Inventory *inventory.Inventory // the leader's inventory: the web UI reads pod counts; the node-agent reconciler marks the cluster
	Recorder  events.EventRecorder
	Hooks     *Hooks
	Log       logr.Logger
	// Ready turns true, and stays true, once the initial inventory is catalogued and matched.
	Ready func(ctx context.Context) bool
}

// Registrar adds an output package's runnables and controllers to the manager.
type Registrar func(m manager.Manager, d Deps) error
