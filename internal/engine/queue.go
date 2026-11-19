package engine

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

const (
	// drainBatch is how many queued owners one Recompute call takes at most.
	drainBatch = 256
	// drainRetry is how long Start waits before retrying owners whose recompute failed.
	drainRetry = 10 * time.Second
	// expiryInterval and pruneInterval are the periods of Start's jobs.
	expiryInterval = time.Minute
	pruneInterval  = 24 * time.Hour
)

// triggerRank orders the triggers a queued owner can hold: when an owner is queued again, the
// higher-ranked trigger wins.
func triggerRank(t model.Trigger) int {
	switch t {
	case model.TriggerNewAdvisory:
		return 3
	case model.TriggerInventoryChange:
		return 2
	case model.TriggerPriorityChange:
		return 1
	}
	return 0
}

// enqueue queues keys for a recompute with trig and wakes the worker.
func (e *Engine) enqueue(keys []string, trig model.Trigger) {
	if len(keys) == 0 {
		return
	}
	e.merge(keys, trig)
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// merge adds keys to the queue without waking the worker.
func (e *Engine) merge(keys []string, trig model.Trigger) {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	for _, k := range keys {
		if cur, ok := e.pending[k]; !ok || triggerRank(trig) > triggerRank(cur) {
			e.pending[k] = trig
		}
	}
}

// take removes up to n queued owners and counts the batch as running, under the queue lock, so
// Idle never sees the batch neither queued nor running. It returns nil when the queue is empty.
func (e *Engine) take(n int) map[string]model.Trigger {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	if len(e.pending) == 0 {
		return nil
	}
	batch := make(map[string]model.Trigger, min(n, len(e.pending)))
	for k, t := range e.pending {
		if len(batch) == n {
			break
		}
		batch[k] = t
		delete(e.pending, k)
	}
	e.running.Add(1)
	return batch
}

// Drain recomputes every queued owner, up to 256 at a time, one Recompute per trigger. Owners whose
// recompute failed are queued again without waking the worker, and Drain returns the error.
func (e *Engine) Drain(ctx context.Context) error {
	for {
		batch := e.take(drainBatch)
		if batch == nil {
			return nil
		}
		err := e.drainBatch(ctx, batch)
		e.running.Add(-1)
		if err != nil {
			return err
		}
	}
}

func (e *Engine) drainBatch(ctx context.Context, batch map[string]model.Trigger) error {
	byTrigger := map[model.Trigger][]string{}
	for k, t := range batch {
		byTrigger[t] = append(byTrigger[t], k)
	}
	triggers := slices.SortedFunc(maps.Keys(byTrigger), func(a, b model.Trigger) int {
		return cmp.Or(cmp.Compare(triggerRank(b), triggerRank(a)), cmp.Compare(a, b))
	})
	var errs []error
	for _, t := range triggers {
		keys := byTrigger[t]
		slices.Sort(keys)
		failed, err := e.recompute(ctx, keys, t)
		if err != nil {
			e.merge(failed, t)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Start is the leader-only worker (a manager.Runnable). It prunes once, then drains the queue
// whenever owners are queued, checks exception expiry every minute and prunes daily, until ctx is
// done. Errors are logged, never returned; a failed drain is retried after a pause.
func (e *Engine) Start(ctx context.Context) error {
	e.prune(ctx)
	expiry := time.NewTicker(expiryInterval)
	defer expiry.Stop()
	prune := time.NewTicker(pruneInterval)
	defer prune.Stop()
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-expiry.C:
			if err := e.CheckExceptionExpiry(ctx); err != nil {
				e.o.Log.Error(err, "exception expiry check failed")
			}
			continue
		case <-prune.C:
			e.prune(ctx)
			continue
		case <-e.wake:
		case <-retry:
		}
		retry = nil
		if err := e.Drain(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			e.o.Log.Error(err, "recomputing findings failed; retrying", "after", drainRetry)
			retry = time.After(drainRetry)
		}
	}
}

// prune runs Prune and logs the outcome.
func (e *Engine) prune(ctx context.Context) {
	n, err := e.Prune(ctx)
	switch {
	case err != nil:
		e.o.Log.Error(err, "pruning resolved findings failed")
	case n > 0:
		e.o.Log.Info("pruned resolved findings", "count", n)
	}
}
