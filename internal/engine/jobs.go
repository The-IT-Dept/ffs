package engine

import (
	"context"
	"fmt"
	"time"
)

// unusedImageRetention is how long an image no owner runs and no suggestion holds is kept: long
// enough for a rollback to find it catalogued, short enough that superseded rollout digests do not
// fill the volume or the weekly full re-match.
const unusedImageRetention = 7 * 24 * time.Hour

// CheckExceptionExpiry queues every owner when an exception rule expired since the last check, so
// the findings it excepted reopen with trigger ExceptionExpired. The first check covers expiries
// since New; expiries before startup are covered by the Exception reconciler's initial pass.
func (e *Engine) CheckExceptionExpiry(ctx context.Context) error {
	if e.o.Exceptions == nil {
		return nil
	}
	e.expiryMu.Lock()
	defer e.expiryMu.Unlock()
	now := e.now()
	rules, err := e.o.Exceptions.ExceptionRules(ctx)
	if err != nil {
		return fmt.Errorf("engine: exception rules: %w", err)
	}
	for _, r := range rules {
		if r.Expires.After(e.lastCheck) && !r.Expires.After(now) {
			if err := e.OnExceptionsChanged(ctx); err != nil {
				return err // lastCheck stays, so the next check retries
			}
			break
		}
	}
	e.lastCheck = now
	return nil
}

// Prune deletes resolved findings, and their history, older than the retention period, then the
// images no owner has run and no upgrade suggestion has held for a week (superseded rollout digests
// and stale candidates). It returns the number of findings deleted.
func (e *Engine) Prune(ctx context.Context) (int, error) {
	now := e.now()
	n, err := e.o.Store.PruneResolved(ctx, now.Add(-e.o.Config.Retention.Resolved))
	if err != nil {
		return 0, fmt.Errorf("engine: prune resolved findings: %w", err)
	}
	images, err := e.o.Store.PruneImages(ctx, now, unusedImageRetention)
	if err != nil {
		return n, fmt.Errorf("engine: prune unused images: %w", err)
	}
	if images > 0 {
		e.o.Log.Info("pruned unused images", "count", images)
	}
	return n, nil
}
