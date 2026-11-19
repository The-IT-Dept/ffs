package notify_test

import (
	"encoding/json"
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
