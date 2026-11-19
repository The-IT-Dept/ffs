package inventory

import (
	"context"
	"sort"
	"sync"
	"time"
)

// batcher collects keys and flushes them in batches. A batch flushes window after its first key,
// so continuous churn cannot starve it. Keys are de-duplicated; keys that arrive during a flush go
// to the next batch.
type batcher struct {
	window time.Duration
	flush  func(ctx context.Context, keys []string)

	mu      sync.Mutex
	pending map[string]struct{}
	first   time.Time     // arrival of the pending batch's first key
	kick    chan struct{} // signalled when a batch opens
}

func newBatcher(window time.Duration, flush func(ctx context.Context, keys []string)) *batcher {
	return &batcher{window: window, flush: flush, pending: map[string]struct{}{}, kick: make(chan struct{}, 1)}
}

// Add queues keys for the next flush.
func (b *batcher) Add(keys ...string) {
	if len(keys) == 0 {
		return
	}
	b.mu.Lock()
	opened := len(b.pending) == 0
	if opened {
		b.first = time.Now()
	}
	for _, k := range keys {
		b.pending[k] = struct{}{}
	}
	b.mu.Unlock()
	if opened {
		select {
		case b.kick <- struct{}{}:
		default:
		}
	}
}

// Run flushes batches until ctx is done.
func (b *batcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.kick:
		}
		b.mu.Lock()
		wait := time.Until(b.first.Add(b.window))
		b.mu.Unlock()
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		b.mu.Lock()
		keys := make([]string, 0, len(b.pending))
		for k := range b.pending {
			keys = append(keys, k)
		}
		b.pending = map[string]struct{}{}
		b.mu.Unlock()
		if len(keys) > 0 {
			sort.Strings(keys)
			b.flush(ctx, keys)
		}
	}
}
