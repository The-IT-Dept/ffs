package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	// GiveUpAfter is how long after its first attempt a delivery whose sends keep failing
	// transiently is given up: its first failed send at or after that time fails it for good. The
	// backoff between sends stays capped at 15m, so an endpoint that is down for less than a day
	// still gets every queued alert.
	GiveUpAfter = 24 * time.Hour

	// MaxPending is the most deliveries a target holds queued. Past that, the oldest are dropped and
	// counted (ffs_notify_deliveries_total{result="dropped"}): a receiver that is down for days, or
	// gone while it answers with transient errors, then costs a bounded outbox, and gets the most
	// recent alerts when it returns.
	MaxPending = 1000

	drainBatch  = 200 // deliveries read per target per drain
	sendTimeout = 30 * time.Second

	baseBackoff   = 5 * time.Second
	maxBackoff    = 15 * time.Minute
	maxRetryAfter = time.Hour

	goneReason = "endpoint returned HTTP 410 Gone"
)

// NextAttempt is the wait before retrying after the attempt-th failed send: 5s doubling per
// attempt up to 15m, with ±20% jitter from rnd in [0,1]. A longer Retry-After from the endpoint
// wins, up to 1h.
func NextAttempt(attempt int, retryAfter time.Duration, rnd float64) time.Duration {
	d := maxBackoff
	if n := max(attempt, 1) - 1; n < 20 && baseBackoff<<n < maxBackoff {
		d = baseBackoff << n
	}
	d = time.Duration(math.Round(float64(d) * (0.8 + 0.4*rnd)))
	if retryAfter > d {
		d = min(retryAfter, maxRetryAfter)
	}
	return d
}

// DrainOnce sends the deliveries that are due and waits for the sends. Each target is drained on
// its own: its deliveries are read separately, up to 200, and sent in order, in parallel with the
// other targets, so one target's backlog or slow endpoint never delays another target's alerts.
// Only targets that can be sent to now are drained: deliveries of unregistered, disabled or paused
// targets, and of a target backing off after a failed send, stay pending. When ctx is cancelled
// mid-send the attempt is not recorded, so the delivery is sent again later with the same ID.
func (e *Engine) DrainOnce(ctx context.Context) error {
	wait, err := e.startDrains(ctx)
	if err != nil {
		return err
	}
	return wait()
}

// startDrains starts a drain for every sendable target that has none running, and returns a
// function that waits for those drains and returns their errors. Start calls it on every tick
// without waiting, so a target still sending a long backlog is skipped while the others are
// drained again.
func (e *Engine) startDrains(ctx context.Context) (wait func() error, err error) {
	now := e.now()
	ready, err := e.sendable(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("notify: targets: %w", err)
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, uid := range slices.Sorted(maps.Keys(ready)) {
		t := ready[uid]
		if !e.claimDrain(uid) {
			continue
		}
		wg.Go(func() {
			defer e.releaseDrain(uid)
			if err := e.drainTarget(ctx, t, now); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("notify: target %s: %w", t.cfg.Name, err))
				mu.Unlock()
			}
		})
	}
	return func() error {
		wg.Wait()
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.Join(errs...)
	}, nil
}

// claimDrain marks the target uid as draining; false when a drain of it is already running.
func (e *Engine) claimDrain(uid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.draining[uid] {
		return false
	}
	e.draining[uid] = true
	return true
}

func (e *Engine) releaseDrain(uid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.draining, uid)
}

// sendable returns, by UID, the targets that can be sent to at now: registered, not paused, not
// disabled, and not backing off after a failed send.
func (e *Engine) sendable(ctx context.Context, now time.Time) (map[string]*target, error) {
	rows, err := e.st.NotifyTargets(ctx)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]*target{}
	for _, r := range rows {
		if t := e.targets[r.Target]; t != nil && !t.cfg.Paused && !r.Disabled && !e.backoff[r.Target].After(now) {
			out[r.Target] = t
		}
	}
	return out, nil
}

// current reports whether t is still the registered, unpaused target of its UID, with the same
// endpoint and settings. A drain checks it before each send, so pausing a target, or detaching or
// re-pointing it, stops a backlog mid-way; the rest stays pending.
func (e *Engine) current(t *target) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	cur := e.targets[t.cfg.UID]
	return cur != nil && !cur.cfg.Paused && cur.cfg.ConfigHash == t.cfg.ConfigHash
}

// drainTarget sends the target's deliveries due at now in outbox order: oldest pass first, and
// within a pass by priority (see delivery). After a failure that is the endpoint's rather than the
// message's (anything but Permanent or Gone), the rest wait as long as the failed delivery does, so
// an endpoint that is down costs one send timeout per retry rather than one per queued delivery.
// The wait is kept in memory: after a restart the target is tried again at once.
func (e *Engine) drainTarget(ctx context.Context, t *target, now time.Time) error {
	ds, err := e.st.PendingDeliveriesFor(ctx, now, []string{t.cfg.UID}, drainBatch)
	if err != nil {
		return fmt.Errorf("pending deliveries: %w", err)
	}
	for _, d := range ds {
		if !e.current(t) {
			return nil
		}
		var m Message
		var sendErr error
		if err := json.Unmarshal(d.Payload, &m); err != nil {
			sendErr = &DeliveryError{Permanent: true, Msg: "the stored message could not be read: " + err.Error()}
		} else {
			sctx, cancel := context.WithTimeout(ctx, sendTimeout)
			sendErr = t.sink.Send(sctx, m)
			cancel()
		}
		if err := ctx.Err(); err != nil {
			return err // shutting down: the attempt is not recorded, so the delivery is sent again
		}
		a, retryAt := e.attempt(d, sendErr)
		metrics.NotifyDeliveries.WithLabelValues(t.cfg.Name, deliveryResult(a)).Inc()
		if err := e.st.RecordAttempt(ctx, a); err != nil {
			return err
		}
		switch {
		case a.Disable:
			return nil // the rest were dropped with the target
		case !retryAt.IsZero():
			e.mu.Lock()
			if _, ok := e.targets[t.cfg.UID]; ok { // not when it was unregistered meanwhile
				e.backoff[t.cfg.UID] = retryAt
			}
			e.mu.Unlock()
			return nil
		}
	}
	return nil
}

// droppedReason is the last error of a delivery dropped to keep its target within MaxPending.
var droppedReason = fmt.Sprintf("dropped: more than %d messages were waiting for this target", MaxPending)

// commit applies c, then holds the target t to MaxPending queued deliveries when c queued any: the
// oldest past that are dropped, and counted in the delivery metric as "dropped".
func (e *Engine) commit(ctx context.Context, t *target, c store.NotifyCommit) error {
	if err := e.st.CommitNotify(ctx, c); err != nil || len(c.Deliveries) == 0 {
		return err
	}
	n, err := e.st.DropOldestPending(ctx, c.Target, MaxPending, droppedReason)
	if n > 0 {
		metrics.NotifyDeliveries.WithLabelValues(t.cfg.Name, "dropped").Add(float64(n))
	}
	return err
}

// deliveryResult names the outcome of attempt a for the delivery metric: success, failed (the
// delivery will not be sent again) or retry.
func deliveryResult(a store.DeliveryAttempt) string {
	switch a.State {
	case store.DeliverySent:
		return "success"
	case store.DeliveryFailed:
		return "failed"
	}
	return "retry"
}

// attempt classifies the outcome of sending d. retryAt is set after a failure that is not
// Permanent or Gone: when the endpoint can be tried again, which is also when d is retried unless
// its first attempt was GiveUpAfter or more ago. Once d has been attempted, its NotBefore is the
// time of that first attempt (store.RecordAttempt moves it there).
func (e *Engine) attempt(d store.Delivery, err error) (a store.DeliveryAttempt, retryAt time.Time) {
	now := e.now()
	a = store.DeliveryAttempt{ID: d.ID, Target: d.Target, At: now}
	if err == nil {
		a.State = store.DeliverySent
		return a, time.Time{}
	}
	a.Error = err.Error()
	var de *DeliveryError
	if errors.As(err, &de) {
		a.HTTPStatus = de.Status
	}
	switch {
	case de != nil && de.Gone:
		a.State, a.Disable, a.DisableReason = store.DeliveryFailed, true, goneReason
		return a, time.Time{}
	case de != nil && de.Permanent:
		a.State = store.DeliveryFailed
		return a, time.Time{}
	}
	attempts := d.Attempts + 1
	var retryAfter time.Duration
	if de != nil {
		retryAfter = de.RetryAfter
	}
	retryAt = now.Add(NextAttempt(attempts, retryAfter, e.o.Rand()))
	first := now
	if d.Attempts > 0 && !d.NotBefore.IsZero() {
		first = d.NotBefore
	}
	if now.Sub(first) >= GiveUpAfter {
		a.State = store.DeliveryFailed
	} else {
		a.State, a.NextAttempt = store.DeliveryPending, retryAt
	}
	return a, retryAt
}
