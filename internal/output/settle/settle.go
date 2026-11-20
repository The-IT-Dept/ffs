// Package settle debounces the engine's change signal for the output writers, so a burst of engine
// changes leads to one read of the store instead of one per change.
package settle

import (
	"context"
	"time"
)

// Window is how long a writer waits after a change signal before it reads the store.
const Window = time.Second

// Wait returns d after it is called, absorbing every signal on changed meanwhile; call it after
// receiving a signal. A steady stream of signals delays a writer by d at most. It returns false
// when ctx ends first.
func Wait(ctx context.Context, changed <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-changed:
		case <-t.C:
			return true
		}
	}
}
