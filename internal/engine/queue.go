package engine

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/findings"
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

// triggerRank orders the top triggers of queued owners' causes: Drain recomputes the owners a feed
// queued first.
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

// enqueue queues keys for a recompute with cause c and wakes the worker.
func (e *Engine) enqueue(keys []string, c findings.Causes) {
	if len(keys) == 0 {
		return
	}
	e.merge(keys, c)
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// merge adds keys to the queue without waking the worker. An owner already queued keeps its causes
// and adds c, so its recompute labels each transition with the cause that explains it.
func (e *Engine) merge(keys []string, c findings.Causes) {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	for _, k := range keys {
		e.pending[k] |= c
	}
}

// take removes up to n queued owners and counts the batch as running, under the queue lock, so
// Idle never sees the batch neither queued nor running. It returns nil when the queue is empty.
func (e *Engine) take(n int) map[string]findings.Causes {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	if len(e.pending) == 0 {
		return nil
	}
	batch := make(map[string]findings.Causes, min(n, len(e.pending)))
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

// Drain recomputes every queued owner, up to 256 at a time, one Recompute per set of causes. Owners
// whose recompute failed are queued again without waking the worker, and Drain returns the error.
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

func (e *Engine) drainBatch(ctx context.Context, batch map[string]findings.Causes) error {
	byCauses := map[findings.Causes][]string{}
	for k, c := range batch {
		byCauses[c] = append(byCauses[c], k)
	}
	causes := slices.SortedFunc(maps.Keys(byCauses), func(a, b findings.Causes) int {
		return cmp.Or(cmp.Compare(triggerRank(b.Top()), triggerRank(a.Top())), cmp.Compare(a, b))
	})
	var errs []error
	for _, c := range causes {
		keys := byCauses[c]
		slices.Sort(keys)
		failed, err := e.recompute(ctx, keys, c)
		if err != nil {
			e.merge(failed, c)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Start is the leader-only worker (a manager.Runnable). It prunes once and queues every owner, then
// drains the queue whenever owners are queued, checks exception expiry every minute and prunes
// daily, until ctx is done. Errors are logged, never returned; a failed drain is retried after a
// pause.
//
// The queue lives in memory, while the feeds advance their watermarks once their handler has
// written matches or enrichment and queued owners. Queuing every owner at start redoes whatever a
// restart cut short; Diff emits only real changes, so the pass is idempotent.
func (e *Engine) Start(ctx context.Context) error {
	e.prune(ctx)
	caughtUp := e.catchUp(ctx)
	expiry := time.NewTicker(expiryInterval)
	defer expiry.Stop()
	prune := time.NewTicker(pruneInterval)
	defer prune.Stop()
	var retry <-chan time.Time
	if !caughtUp {
		retry = time.After(drainRetry)
	}
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
		if !caughtUp {
			caughtUp = e.catchUp(ctx)
		}
		if err := e.Drain(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			e.o.Log.Error(err, "recomputing findings failed; retrying", "after", drainRetry)
			retry = time.After(drainRetry)
		} else if !caughtUp {
			retry = time.After(drainRetry)
		}
	}
}

// catchUp queues every owner, reporting whether it could.
func (e *Engine) catchUp(ctx context.Context) bool {
	if err := e.enqueueAll(ctx, findings.CauseInventory); err != nil {
		e.o.Log.Error(err, "queuing every owner at start failed; retrying", "after", drainRetry)
		return false
	}
	return true
}

// prune runs Prune and logs the outcome.
func (e *Engine) prune(ctx context.Context) {
	n, err := e.Prune(ctx)
	switch {
	case err != nil:
		e.o.Log.Error(err, "pruning the store failed")
	case n > 0:
		e.o.Log.Info("pruned resolved findings", "count", n)
	}
}
