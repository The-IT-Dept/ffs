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

	"github.com/the-it-dept/ffs/internal/store"
)

const (
	// MaxAttempts is the number of sends after which a delivery that keeps failing is given up.
	MaxAttempts = 12

	drainBatch    = 200 // deliveries read per DrainOnce
	drainParallel = 8   // targets sent to at once; each target's deliveries go in order
	sendTimeout   = 30 * time.Second

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

// DrainOnce sends the deliveries that are due, up to 200: targets in parallel, each target's in
// order. Only targets that can be sent to now are read: deliveries of unregistered or disabled
// targets, and of a target backing off after a failed send, stay pending and take no place in the
// batch. When ctx is cancelled mid-send the attempt is not recorded, so the delivery is sent again
// later with the same ID.
func (e *Engine) DrainOnce(ctx context.Context) error {
	now := e.now()
	ready, err := e.sendable(ctx, now)
	if err != nil {
		return fmt.Errorf("notify: targets: %w", err)
	}
	if len(ready) == 0 {
		return nil
	}
	ds, err := e.st.PendingDeliveriesFor(ctx, now, slices.Sorted(maps.Keys(ready)), drainBatch)
	if err != nil {
		return fmt.Errorf("notify: pending deliveries: %w", err)
	}
	var order []string
	byTarget := map[string][]store.Delivery{}
	for _, d := range ds {
		if _, ok := byTarget[d.Target]; !ok {
			order = append(order, d.Target)
		}
		byTarget[d.Target] = append(byTarget[d.Target], d)
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
		sem  = make(chan struct{}, drainParallel)
	)
	for _, uid := range order {
		t := ready[uid]
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := e.drainTarget(ctx, t, byTarget[uid]); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("notify: target %s: %w", t.cfg.Name, err))
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(errs...)
}

// sendable returns, by UID, the targets that can be sent to at now: registered, not disabled, and
// not backing off after a failed send.
func (e *Engine) sendable(ctx context.Context, now time.Time) (map[string]*target, error) {
	rows, err := e.st.NotifyTargets(ctx)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]*target{}
	for _, r := range rows {
		if t := e.targets[r.Target]; t != nil && !r.Disabled && !e.backoff[r.Target].After(now) {
			out[r.Target] = t
		}
	}
	return out, nil
}

// drainTarget sends ds in order. After a failure that is the endpoint's rather than the message's
// (anything but Permanent or Gone), the rest wait as long as the failed delivery does, so an
// endpoint that is down costs one send timeout per retry rather than one per queued delivery. The
// wait is kept in memory: after a restart the target is tried again at once.
func (e *Engine) drainTarget(ctx context.Context, t *target, ds []store.Delivery) error {
	for _, d := range ds {
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

// attempt classifies the outcome of sending d. retryAt is set after a failure that is not
// Permanent or Gone: when the endpoint can be tried again, which is also when d is retried unless
// it has used up its attempts.
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
	if attempts >= MaxAttempts {
		a.State = store.DeliveryFailed
	} else {
		a.State, a.NextAttempt = store.DeliveryPending, retryAt
	}
	return a, retryAt
}
