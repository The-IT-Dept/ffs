package notify_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/store"
)

func TestDrain_NextAttemptBounds(t *testing.T) {
	assert.Equal(t, 4*time.Second, notify.NextAttempt(1, 0, 0)) // 5s base, ±20% jitter
	assert.Equal(t, 6*time.Second, notify.NextAttempt(1, 0, 1))
	assert.Equal(t, 10*time.Second, notify.NextAttempt(2, 0, 0.5))
	assert.Equal(t, 15*time.Minute, notify.NextAttempt(20, 0, 0.5))             // cap 15m
	assert.Equal(t, 15*time.Minute, notify.NextAttempt(100, 0, 0.5))            // no overflow
	assert.Equal(t, 30*time.Second, notify.NextAttempt(2, 30*time.Second, 0.5)) // Retry-After wins when larger
	assert.Equal(t, 10*time.Second, notify.NextAttempt(2, 3*time.Second, 0.5))  // and only then
	assert.Equal(t, time.Hour, notify.NextAttempt(2, 3*time.Hour, 0.5))         // Retry-After capped at 1h
}

// pendingHarness has one target past its baseline and one urgent alert queued for it.
func pendingHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.target("ops")
	h.process()
	h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	require.NoError(t, h.eng.ProcessOnce(ctx))
	return h
}

func (h *harness) deliveries() []store.Delivery {
	h.t.Helper()
	ds, err := h.st.ListDeliveries(ctx, "uid-ops", 0)
	require.NoError(h.t, err)
	return ds
}

func TestDrain_RetryAfterHonoured(t *testing.T) {
	h := pendingHarness(t)
	h.sink.failNext(1, &notify.DeliveryError{Status: 429, RetryAfter: 30 * time.Second, Msg: "hooks.example returned HTTP 429"})
	start := h.now
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))
	d := h.deliveries()[0]
	assert.Equal(t, store.DeliveryPending, d.State)
	assert.Equal(t, 429, d.HTTPStatus)
	assert.Equal(t, 1, d.Attempts)

	h.now = start.Add(29 * time.Second)
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Equal(t, 2, h.sink.calls) // the baseline and the first attempt
	h.now = start.Add(30 * time.Second)
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1)
	st, _, err := h.eng.Status(ctx, "uid-ops")
	require.NoError(t, err)
	assert.Zero(t, st.ConsecutiveFailures)
	assert.Equal(t, h.now, st.LastDeliveryAt)
}

func TestDrain_GiveUpAfterMaxAttempts(t *testing.T) {
	h := pendingHarness(t)
	failure := &notify.DeliveryError{Status: 503, Msg: "hooks.example returned HTTP 503"}
	h.sink.failNext(notify.MaxAttempts+1, failure)
	for range notify.MaxAttempts {
		require.NoError(t, h.eng.DrainOnce(ctx))
		h.now = h.now.Add(time.Hour)
	}
	d := h.deliveries()[0]
	assert.Equal(t, store.DeliveryFailed, d.State)
	assert.Equal(t, notify.MaxAttempts, d.Attempts)
	st, _, err := h.eng.Status(ctx, "uid-ops")
	require.NoError(t, err)
	assert.Equal(t, 12, st.ConsecutiveFailures)
	assert.Equal(t, failure.Msg, st.LastError)
	assert.False(t, st.Disabled)

	calls := h.sink.calls
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Equal(t, calls, h.sink.calls) // given up: not sent again
}

func TestDrain_PermanentFailsAtOnce(t *testing.T) {
	h := pendingHarness(t)
	h.sink.failNext(1, &notify.DeliveryError{Status: 404, Permanent: true, Msg: "hooks.example returned HTTP 404"})
	require.NoError(t, h.eng.DrainOnce(ctx))
	d := h.deliveries()[0]
	assert.Equal(t, store.DeliveryFailed, d.State)
	assert.Equal(t, 1, d.Attempts)
}

func TestDrain_GoneDisablesTarget(t *testing.T) {
	h := pendingHarness(t)
	h.open(dep("a", "y"), "CVE-2026-0002", urgent)
	require.NoError(t, h.eng.ProcessOnce(ctx))
	h.sink.failNext(1, &notify.DeliveryError{Status: 410, Gone: true, Msg: "hooks.example returned HTTP 410"})
	require.NoError(t, h.eng.DrainOnce(ctx))

	st, _, err := h.eng.Status(ctx, "uid-ops")
	require.NoError(t, err)
	assert.True(t, st.Disabled)
	assert.Equal(t, "endpoint returned HTTP 410 Gone", st.DisabledReason)
	states := map[store.DeliveryState]int{}
	for _, d := range h.deliveries() {
		states[d.State]++
	}
	assert.Equal(t, map[store.DeliveryState]int{store.DeliverySent: 1, store.DeliveryFailed: 1, store.DeliveryDropped: 1}, states)

	h.open(dep("a", "z"), "CVE-2026-0003", urgent)
	require.NoError(t, h.eng.ProcessOnce(ctx))
	cur, _ := h.st.Cursor(ctx, "notify:uid-ops")
	maxID, _ := h.st.MaxTransitionID(ctx)
	assert.Equal(t, maxID, cur)
	assert.Len(t, h.deliveries(), 3) // nothing enqueued

	h.target("ops") // same ConfigHash
	st, _, _ = h.eng.Status(ctx, "uid-ops")
	assert.True(t, st.Disabled)
	h.target("ops", func(c *notify.TargetConfig) { c.ConfigHash = "h2" })
	st, _, _ = h.eng.Status(ctx, "uid-ops")
	assert.False(t, st.Disabled)
	h.open(dep("a", "w"), "CVE-2026-0004", urgent)
	h.process()
	assert.Equal(t, []string{"CVE-2026-0004"}, advisories(h.sink.sent))
}

func TestDrain_UnregisteredTargetLeftPending(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	payload, err := json.Marshal(notify.Message{ID: "ffs_ghost", Kind: notify.KindImmediate, Title: "t"})
	require.NoError(t, err)
	require.NoError(t, h.st.CommitNotify(ctx, store.NotifyCommit{Target: "uid-ghost",
		Deliveries: []store.Delivery{{ID: "ffs_ghost", Kind: "immediate", Payload: payload, CreatedAt: h.now}}}))
	require.NoError(t, h.eng.DrainOnce(ctx))
	ds, err := h.st.ListDeliveries(ctx, "uid-ghost", 0)
	require.NoError(t, err)
	require.Len(t, ds, 1)
	assert.Equal(t, store.DeliveryPending, ds[0].State)
	assert.Zero(t, ds[0].Attempts)
	assert.Zero(t, h.sink.calls)
}

func TestDrain_FailingEndpointHoldsBackTheRest(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	dev := &fakeSink{}
	devCfg := h.cfg("ops")
	devCfg.UID, devCfg.Name = "uid-dev", "dev"
	require.NoError(t, h.eng.Register(ctx, devCfg, dev))
	h.process() // baselines
	h.batch(finding(dep("a", "x"), "CVE-2026-0001", urgent), finding(dep("a", "x"), "CVE-2026-0002", urgent),
		finding(dep("a", "x"), "CVE-2026-0003", urgent))
	require.NoError(t, h.eng.ProcessOnce(ctx))

	h.sink.failNext(1, context.DeadlineExceeded) // the endpoint timed out
	start, calls := h.now, h.sink.calls
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Equal(t, calls+1, h.sink.calls)             // one failed send, then the rest wait
	assert.Len(t, dev.ofKind(notify.KindImmediate), 3) // another target is not held up
	var head string
	attempts := map[int]int{}
	for _, d := range h.deliveries() {
		if d.Kind != string(notify.KindImmediate) {
			continue
		}
		assert.Equal(t, store.DeliveryPending, d.State)
		attempts[d.Attempts]++
		if d.Attempts == 1 {
			head = d.ID
		}
	}
	assert.Equal(t, map[int]int{0: 2, 1: 1}, attempts)

	h.now = start.Add(4 * time.Second)
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Equal(t, calls+1, h.sink.calls) // still backing off: 5s at Rand 0.5

	h.now = start.Add(5 * time.Second)
	require.NoError(t, h.eng.DrainOnce(ctx))
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 3)
	assert.Equal(t, head, imm[0].ID) // the failed delivery still goes first
	st, _, err := h.eng.Status(ctx, "uid-ops")
	require.NoError(t, err)
	assert.Zero(t, st.ConsecutiveFailures)
}

func TestDrain_UnsendableBacklogTakesNoPlace(t *testing.T) {
	h := pendingHarness(t) // one urgent alert queued for ops
	h.target("dead")
	require.NoError(t, h.st.RecordAttempt(ctx, store.DeliveryAttempt{ID: "none", Target: "uid-dead", At: h.now,
		State: store.DeliveryFailed, Disable: true, DisableReason: "endpoint returned HTTP 410 Gone"}))
	payload, err := json.Marshal(notify.Message{ID: "ffs_old", Kind: notify.KindImmediate, Title: "t"})
	require.NoError(t, err)
	backlog := func(uid string) {
		ds := make([]store.Delivery, 0, 200)
		for i := range 200 { // a whole batch, all older than the ops alert
			ds = append(ds, store.Delivery{ID: fmt.Sprintf("ffs_%s_%03d", uid, i), Kind: "immediate", Payload: payload,
				CreatedAt: h.now.Add(-time.Hour)})
		}
		require.NoError(t, h.st.CommitNotify(ctx, store.NotifyCommit{Target: uid, Deliveries: ds}))
	}
	backlog("uid-ghost") // never registered
	backlog("uid-dead")  // registered but disabled

	require.NoError(t, h.eng.DrainOnce(ctx))
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 1)
	assert.Equal(t, "ops", imm[0].TargetName)
	for _, uid := range []string{"uid-ghost", "uid-dead"} {
		ds, err := h.st.ListDeliveries(ctx, uid, 0)
		require.NoError(t, err)
		require.Len(t, ds, 200)
		for _, d := range ds {
			assert.Equal(t, store.DeliveryPending, d.State)
			assert.Zero(t, d.Attempts)
		}
	}
}

// queueBacklog queues n deliveries for uid, all created an hour before now.
func (h *harness) queueBacklog(uid string, n int) {
	h.t.Helper()
	payload, err := json.Marshal(notify.Message{ID: "ffs_old", Kind: notify.KindImmediate, Title: "backlog"})
	require.NoError(h.t, err)
	ds := make([]store.Delivery, 0, n)
	for i := range n {
		ds = append(ds, store.Delivery{ID: fmt.Sprintf("ffs_%s_%04d", uid, i), Kind: "immediate", Payload: payload,
			CreatedAt: h.now.Add(-time.Hour)})
	}
	require.NoError(h.t, h.st.CommitNotify(ctx, store.NotifyCommit{Target: uid, Deliveries: ds}))
}

// TestDrain_BacklogDoesNotDelayOtherTargets pins per-target draining (F31): a healthy target with
// a backlog older than everything else no longer fills the batch, so another target's urgent alert
// goes out on the first drain.
func TestDrain_BacklogDoesNotDelayOtherTargets(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	busy := &fakeSink{}
	busyCfg := h.cfg("ops")
	busyCfg.UID, busyCfg.Name = "uid-busy", "busy"
	require.NoError(t, h.eng.Register(ctx, busyCfg, busy))
	h.process() // baselines
	h.queueBacklog("uid-busy", 400)
	h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	require.NoError(t, h.eng.ProcessOnce(ctx))

	require.NoError(t, h.eng.DrainOnce(ctx))
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 1, "the urgent alert goes out on the first drain")
	assert.Equal(t, "CVE-2026-0001", imm[0].Items[0].AdvisoryID)
	assert.Len(t, busy.ofKind(notify.KindImmediate), 200, "the busy target sends a batch of its own")
}

// blockingSink blocks every Send until release is closed, after signalling started once.
type blockingSink struct {
	fakeSink
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingSink) Send(ctx context.Context, m notify.Message) error {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.fakeSink.Send(ctx, m)
}

// TestDrain_SlowTargetDoesNotGateTheNextDrain pins the other half of F31: while one target is
// still sending, the next drain sends the other targets' alerts instead of waiting for it, and
// never drains the slow target twice at once.
func TestDrain_SlowTargetDoesNotGateTheNextDrain(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	slow := &blockingSink{started: make(chan struct{}), release: make(chan struct{})}
	slowCfg := h.cfg("ops")
	slowCfg.UID, slowCfg.Name = "uid-slow", "slow"
	require.NoError(t, h.eng.Register(ctx, slowCfg, slow))
	require.NoError(t, h.eng.ProcessOnce(ctx)) // baselines, queued for both
	h.queueBacklog("uid-slow", 3)

	waitSlow, err := h.eng.StartDrains(ctx)
	require.NoError(t, err)
	<-slow.started

	h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	require.NoError(t, h.eng.ProcessOnce(ctx))
	waitNext, err := h.eng.StartDrains(ctx)
	require.NoError(t, err)
	require.NoError(t, waitNext())
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1, "sent while the slow target is still sending")

	close(slow.release)
	require.NoError(t, waitSlow())
	assert.Len(t, slow.ofKind(notify.KindBaseline), 1)
	assert.Len(t, slow.ofKind(notify.KindImmediate), 3, "the backlog drained once, not twice")
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Len(t, slow.ofKind(notify.KindImmediate), 4, "its urgent alert follows on the next drain")
}

// TestDrain_PausedHoldsDeliveries pins spec.paused (F33): nothing is sent to a paused target, not
// even an alert queued before the pause and released by the end of quiet hours, and no retry runs.
// The queued alert waits until the pause is lifted.
func TestDrain_PausedHoldsDeliveries(t *testing.T) {
	h := newHarness(t)
	h.target("ops", func(c *notify.TargetConfig) {
		c.AllowUrgentInQuietHours = false
		c.QuietHours = []notify.TimeInterval{{Times: []notify.TimeRange{{StartTime: "00:00", EndTime: "12:00"}}}}
	})
	h.process() // baseline
	h.at("2026-11-19T10:00Z")
	h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	require.NoError(t, h.eng.ProcessOnce(ctx)) // held until 12:00
	h.target("ops", func(c *notify.TargetConfig) {
		c.Paused = true
		c.AllowUrgentInQuietHours = false
		c.QuietHours = []notify.TimeInterval{{Times: []notify.TimeRange{{StartTime: "00:00", EndTime: "12:00"}}}}
	})

	h.at("2026-11-19T12:05Z")
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate), "nothing is sent while paused")
	for _, d := range h.deliveries() {
		if d.Kind == string(notify.KindImmediate) {
			assert.Equal(t, store.DeliveryPending, d.State)
			assert.Zero(t, d.Attempts)
		}
	}

	h.target("ops")
	require.NoError(t, h.eng.DrainOnce(ctx))
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1, "sent once the pause is lifted")
}
