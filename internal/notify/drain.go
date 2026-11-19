package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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
// order. Deliveries of unregistered or disabled targets stay pending. When ctx is cancelled mid-send
// the attempt is not recorded, so the delivery is sent again later with the same ID.
func (e *Engine) DrainOnce(ctx context.Context) error {
	ds, err := e.st.PendingDeliveries(ctx, e.now(), drainBatch)
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
		t := e.registered(uid)
		if t == nil {
			continue
		}
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

func (e *Engine) drainTarget(ctx context.Context, t *target, ds []store.Delivery) error {
	st, ok, err := e.st.NotifyTarget(ctx, t.cfg.UID)
	if err != nil || !ok || st.Disabled {
		return err
	}
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
		a := e.attempt(d, sendErr)
		if err := e.st.RecordAttempt(ctx, a); err != nil {
			return err
		}
		if a.Disable {
			return nil // the rest were dropped with the target
		}
	}
	return nil
}

// attempt classifies the outcome of sending d.
func (e *Engine) attempt(d store.Delivery, err error) store.DeliveryAttempt {
	now := e.now()
	a := store.DeliveryAttempt{ID: d.ID, Target: d.Target, At: now}
	if err == nil {
		a.State = store.DeliverySent
		return a
	}
	a.Error = err.Error()
	var de *DeliveryError
	if errors.As(err, &de) {
		a.HTTPStatus = de.Status
	}
	attempts := d.Attempts + 1
	switch {
	case de != nil && de.Gone:
		a.State, a.Disable, a.DisableReason = store.DeliveryFailed, true, goneReason
	case de != nil && de.Permanent, attempts >= MaxAttempts:
		a.State = store.DeliveryFailed
	default:
		var retryAfter time.Duration
		if de != nil {
			retryAfter = de.RetryAfter
		}
		a.State, a.NextAttempt = store.DeliveryPending, now.Add(NextAttempt(attempts, retryAfter, e.o.Rand()))
	}
	return a
}
