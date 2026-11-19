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
		if keys := b.take(); len(keys) > 0 {
			b.flush(ctx, keys)
		}
	}
}

// take removes and returns the pending keys, sorted.
func (b *batcher) take() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	keys := make([]string, 0, len(b.pending))
	for k := range b.pending {
		keys = append(keys, k)
	}
	b.pending = map[string]struct{}{}
	sort.Strings(keys)
	return keys
}

// retrier re-queues keys whose flush failed, with a per-key exponential backoff: the first retry
// comes min after the failure and each further failure doubles the wait, up to max. A failure while
// a retry is already scheduled is absorbed by that retry, so a key fails (and is logged) at most
// once per backoff step. A success clears the key's backoff.
type retrier struct {
	min, max time.Duration
	add      func(keys ...string)

	mu   sync.Mutex
	keys map[string]*backoff
}

type backoff struct {
	attempt int
	timer   *time.Timer // set while a retry is scheduled
}

func newRetrier(minDelay, maxDelay time.Duration, add func(keys ...string)) *retrier {
	return &retrier{min: minDelay, max: maxDelay, add: add, keys: map[string]*backoff{}}
}

// fail schedules a retry of key unless one is already scheduled. It returns the retry's attempt
// number and delay, and scheduled false when an earlier retry is still waiting.
func (r *retrier) fail(key string) (attempt int, delay time.Duration, scheduled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.keys[key]
	if b == nil {
		b = &backoff{}
		r.keys[key] = b
	}
	if b.timer != nil {
		return b.attempt, 0, false
	}
	b.attempt++
	delay = r.min
	for i := 1; i < b.attempt && delay < r.max; i++ {
		delay *= 2
	}
	delay = min(delay, r.max)
	b.timer = time.AfterFunc(delay, func() {
		r.mu.Lock()
		current := r.keys[key] == b
		if current {
			b.timer = nil
		}
		r.mu.Unlock()
		if current {
			r.add(key)
		}
	})
	return b.attempt, delay, true
}

// ok clears key's backoff after it flushed successfully.
func (r *retrier) ok(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b := r.keys[key]; b != nil {
		if b.timer != nil {
			b.timer.Stop()
		}
		delete(r.keys, key)
	}
}

// stop cancels every scheduled retry and forgets every backoff.
func (r *retrier) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, b := range r.keys {
		if b.timer != nil {
			b.timer.Stop()
		}
	}
	clear(r.keys)
}
