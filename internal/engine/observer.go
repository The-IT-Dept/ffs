package engine

import (
	"context"
	"slices"
)

// Observer is told when stored matches or findings change. Calls are synchronous, from the
// goroutine that made the change, so an implementation only records or enqueues the work and
// returns; it must not call back into the engine. The slices must not be modified.
type Observer interface {
	// MatchesReplaced follows every ReplaceMatches that changed the matches of digests.
	MatchesReplaced(ctx context.Context, digests []string)
	// OwnersRecomputed follows each Recompute, with the owners whose findings it wrote.
	OwnersRecomputed(ctx context.Context, keys []string)
}

// AddObserver subscribes o to match and findings changes.
func (e *Engine) AddObserver(o Observer) {
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	e.observers = append(e.observers, o)
}

func (e *Engine) observersSnapshot() []Observer {
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	return slices.Clone(e.observers)
}

// matchesReplaced tells every observer that the matches of digests changed.
func (e *Engine) matchesReplaced(ctx context.Context, digests []string) {
	if len(digests) == 0 {
		return
	}
	for _, o := range e.observersSnapshot() {
		o.MatchesReplaced(ctx, digests)
	}
}

// ownersRecomputed tells every observer that the findings of keys were recomputed.
func (e *Engine) ownersRecomputed(ctx context.Context, keys []string) {
	if len(keys) == 0 {
		return
	}
	for _, o := range e.observersSnapshot() {
		o.OwnersRecomputed(ctx, keys)
	}
}
