package engine

import (
	"context"
	"fmt"
)

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
// images catalogued before it that no owner runs and no upgrade suggestion holds (superseded
// rollout digests and stale candidates). It returns the number of findings deleted.
func (e *Engine) Prune(ctx context.Context) (int, error) {
	cutoff := e.now().Add(-e.o.Config.Retention.Resolved)
	n, err := e.o.Store.PruneResolved(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("engine: prune resolved findings: %w", err)
	}
	images, err := e.o.Store.PruneImages(ctx, cutoff)
	if err != nil {
		return n, fmt.Errorf("engine: prune unused images: %w", err)
	}
	if images > 0 {
		e.o.Log.Info("pruned unused images", "count", images)
	}
	return n, nil
}
