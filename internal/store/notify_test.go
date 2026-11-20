package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func ledgerEntry(fp string, p model.Priority, st model.FindingState) LedgerEntry {
	return LedgerEntry{Fingerprint: fp, MaxPriority: p, LastState: st, UpdatedAt: t0}
}

func delivery(id string, created time.Time) Delivery {
	return Delivery{ID: id, Kind: "immediate", Payload: []byte(`{}`), CreatedAt: created}
}

func TestStoreNotify_CommitAtomicAndIdempotent(t *testing.T) {
	st := newStore(t)
	now := t0.Add(time.Hour)
	require.NoError(t, st.PutNotifyTarget(ctx, "u1", "ops", "h1"))
	c := NotifyCommit{Target: "u1", Cursors: map[string]int64{"notify:u1": 42},
		Ledger: []LedgerEntry{ledgerEntry("fp1", model.PriorityHigh, model.StateOpen)}, Deliveries: []Delivery{delivery("d1", t0)},
		BaselineAt: t0, LastDigestAt: t0}
	require.NoError(t, st.CommitNotify(ctx, c))
	c.Cursors = map[string]int64{"notify:u1": 43}
	c.Deliveries[0].Payload = []byte(`{"second":true}`)
	require.NoError(t, st.CommitNotify(ctx, c))

	cur, _ := st.Cursor(ctx, "notify:u1")
	assert.EqualValues(t, 43, cur)
	ds, _ := st.PendingDeliveries(ctx, now, 10)
	require.Len(t, ds, 1) // INSERT OR IGNORE on id
	assert.JSONEq(t, `{}`, string(ds[0].Payload))
	assert.Equal(t, "u1", ds[0].Target)
	assert.Equal(t, DeliveryPending, ds[0].State)
	assert.Equal(t, t0, ds[0].NotBefore) // defaults to CreatedAt
	l, _ := st.Ledger(ctx, "u1", []string{"fp1"})
	assert.Equal(t, model.PriorityHigh, l["fp1"].MaxPriority)
	assert.Equal(t, "u1", l["fp1"].Target)
	ts, ok, _ := st.NotifyTarget(ctx, "u1")
	require.True(t, ok)
	assert.Equal(t, t0, ts.BaselineAt)
	assert.Equal(t, t0, ts.LastDigestAt)

	// A failing commit leaves nothing behind.
	bad := NotifyCommit{Target: "u1", Cursors: map[string]int64{"notify:u1": 99},
		Ledger: []LedgerEntry{ledgerEntry("fp2", model.PriorityUrgent, model.StateOpen)}, Deliveries: []Delivery{{ID: "d2", Kind: "immediate"}}}
	require.Error(t, st.CommitNotify(ctx, bad)) // payload NOT NULL
	cur, _ = st.Cursor(ctx, "notify:u1")
	assert.EqualValues(t, 43, cur)
	l, _ = st.Ledger(ctx, "u1", []string{"fp2"})
	assert.Empty(t, l)
}

func TestStoreNotify_PendingRespectsWindows(t *testing.T) {
	st := newStore(t)
	now := t0.Add(time.Hour)
	later := delivery("later", t0)
	later.NotBefore = now.Add(time.Minute)
	retry := delivery("retry", t0)
	retry.NextAttempt = now.Add(time.Second)
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u1", Deliveries: []Delivery{
		delivery("b", t0.Add(time.Minute)), delivery("c", t0), later, retry, delivery("a", t0.Add(time.Minute)),
		{ID: "sent", Kind: "immediate", Payload: []byte(`{}`), State: DeliverySent, CreatedAt: t0},
	}}))
	ds, err := st.PendingDeliveries(ctx, now, 10)
	require.NoError(t, err)
	var ids []string
	for _, d := range ds {
		ids = append(ids, d.ID)
	}
	assert.Equal(t, []string{"c", "a", "b"}, ids)
	ds, _ = st.PendingDeliveries(ctx, now, 2)
	assert.Len(t, ds, 2)
	ds, _ = st.PendingDeliveries(ctx, now.Add(time.Minute), 10)
	assert.Len(t, ds, 5)
}

func TestStoreNotify_PendingForTargets(t *testing.T) {
	st := newStore(t)
	now := t0.Add(time.Hour)
	var old []Delivery
	for i := range 3 {
		old = append(old, delivery(fmt.Sprintf("old-%d", i), t0))
	}
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u1", Deliveries: old}))
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u2", Deliveries: []Delivery{delivery("b", t0.Add(time.Minute))}}))
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u3", Deliveries: []Delivery{delivery("c", t0.Add(2*time.Minute))}}))

	ids := func(ds []Delivery) []string {
		var out []string
		for _, d := range ds {
			out = append(out, d.ID)
		}
		return out
	}
	ds, err := st.PendingDeliveriesFor(ctx, now, []string{"u2", "u3"}, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"b", "c"}, ids(ds)) // u1's older rows take no place in the batch
	ds, _ = st.PendingDeliveriesFor(ctx, now, []string{"u3", "u1"}, 0)
	assert.Equal(t, []string{"old-0", "old-1", "old-2", "c"}, ids(ds))
	ds, _ = st.PendingDeliveriesFor(ctx, t0, []string{"u2"}, 10)
	assert.Empty(t, ds) // the time windows still apply
	ds, err = st.PendingDeliveriesFor(ctx, now, nil, 10)
	require.NoError(t, err)
	assert.Empty(t, ds)
}

func TestStoreNotify_RecordAttemptUpdatesTarget(t *testing.T) {
	st := newStore(t)
	require.NoError(t, st.PutNotifyTarget(ctx, "u1", "ops", "h1"))
	require.NoError(t, st.PutNotifyTarget(ctx, "u2", "dev", "h1"))
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u1", Deliveries: []Delivery{
		delivery("d1", t0), delivery("d2", t0), delivery("d3", t0)}}))
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u2", Deliveries: []Delivery{delivery("e1", t0)}}))

	at := t0.Add(time.Minute)
	require.NoError(t, st.RecordAttempt(ctx, DeliveryAttempt{ID: "d1", Target: "u1", At: at, State: DeliveryPending,
		NextAttempt: at.Add(5 * time.Second), Error: "HTTP 503", HTTPStatus: 503}))
	ts, _, _ := st.NotifyTarget(ctx, "u1")
	assert.Equal(t, 1, ts.ConsecutiveFailures)
	assert.Equal(t, "HTTP 503", ts.LastError)

	require.NoError(t, st.RecordAttempt(ctx, DeliveryAttempt{ID: "d1", Target: "u1", At: at.Add(time.Minute), State: DeliverySent, HTTPStatus: 200}))
	ts, _, _ = st.NotifyTarget(ctx, "u1")
	assert.Equal(t, at.Add(time.Minute), ts.LastDeliveryAt)
	assert.Empty(t, ts.LastError)
	assert.Zero(t, ts.ConsecutiveFailures)
	log, _ := st.ListDeliveries(ctx, "u1", 0)
	byID := map[string]Delivery{}
	for _, d := range log {
		byID[d.ID] = d
	}
	assert.Equal(t, DeliverySent, byID["d1"].State)
	assert.Equal(t, 2, byID["d1"].Attempts)
	assert.Equal(t, at.Add(time.Minute), byID["d1"].SentAt)
	assert.Equal(t, at.Add(5*time.Second), byID["d1"].NextAttempt) // kept when the attempt gives none

	require.NoError(t, st.RecordAttempt(ctx, DeliveryAttempt{ID: "d2", Target: "u1", At: at, State: DeliveryFailed,
		Error: "HTTP 410", HTTPStatus: 410, Disable: true, DisableReason: "endpoint returned HTTP 410 Gone"}))
	ts, _, _ = st.NotifyTarget(ctx, "u1")
	assert.True(t, ts.Disabled)
	assert.Equal(t, "endpoint returned HTTP 410 Gone", ts.DisabledReason)
	log, _ = st.ListDeliveries(ctx, "u1", 0)
	for _, d := range log {
		byID[d.ID] = d
	}
	assert.Equal(t, DeliveryFailed, byID["d2"].State)
	assert.Equal(t, DeliveryDropped, byID["d3"].State)
	assert.Equal(t, DeliverySent, byID["d1"].State)
	other, _ := st.PendingDeliveries(ctx, at, 10)
	require.Len(t, other, 1)
	assert.Equal(t, "e1", other[0].ID) // another target's deliveries are untouched
}

func TestStoreNotify_PutTargetHashChangeReenables(t *testing.T) {
	st := newStore(t)
	require.NoError(t, st.PutNotifyTarget(ctx, "u1", "ops", "h1"))
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u1", Deliveries: []Delivery{delivery("d1", t0)}}))
	require.NoError(t, st.RecordAttempt(ctx, DeliveryAttempt{ID: "d1", Target: "u1", At: t0, State: DeliveryFailed,
		Error: "gone", Disable: true, DisableReason: "endpoint returned HTTP 410 Gone"}))

	require.NoError(t, st.PutNotifyTarget(ctx, "u1", "ops-renamed", "h1"))
	ts, _, _ := st.NotifyTarget(ctx, "u1")
	assert.True(t, ts.Disabled)
	assert.Equal(t, 1, ts.ConsecutiveFailures)
	assert.Equal(t, "ops-renamed", ts.Name)

	require.NoError(t, st.PutNotifyTarget(ctx, "u1", "ops-renamed", "h2"))
	ts, _, _ = st.NotifyTarget(ctx, "u1")
	assert.False(t, ts.Disabled)
	assert.Empty(t, ts.DisabledReason)
	assert.Zero(t, ts.ConsecutiveFailures)
	assert.Equal(t, "h2", ts.ConfigHash)

	all, err := st.NotifyTargets(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "u1", all[0].Target)
}

func TestStoreNotify_DeleteTargetRemovesState(t *testing.T) {
	st := newStore(t)
	for _, uid := range []string{"u1", "u2"} {
		require.NoError(t, st.PutNotifyTarget(ctx, uid, uid, "h"))
		require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: uid,
			Cursors: map[string]int64{"notify:" + uid: 5, "notify-digest:" + uid: 4},
			Ledger:  []LedgerEntry{ledgerEntry("fp1", model.PriorityUrgent, model.StateOpen)}, Deliveries: []Delivery{delivery("d-"+uid, t0)}}))
	}
	require.NoError(t, st.DeleteNotifyTarget(ctx, "u1"))

	_, ok, _ := st.NotifyTarget(ctx, "u1")
	assert.False(t, ok)
	l, _ := st.Ledger(ctx, "u1", []string{"fp1"})
	assert.Empty(t, l)
	ds, _ := st.ListDeliveries(ctx, "u1", 0)
	assert.Empty(t, ds)
	for _, c := range []string{"notify:u1", "notify-digest:u1"} {
		var n int
		require.NoError(t, st.rdb.QueryRowContext(ctx, `SELECT count(*) FROM cursors WHERE consumer = ?`, c).Scan(&n))
		assert.Zero(t, n, c)
	}
	_, ok, _ = st.NotifyTarget(ctx, "u2")
	assert.True(t, ok)
	l, _ = st.Ledger(ctx, "u2", []string{"fp1"})
	assert.Len(t, l, 1)
	cur, _ := st.Cursor(ctx, "notify-digest:u2")
	assert.EqualValues(t, 4, cur)
}

func TestStoreNotify_RekeyMovesLedger(t *testing.T) {
	st := newStore(t)
	require.NoError(t, st.ApplyFindings(ctx, []model.Finding{fd("fp-ghsa", model.StateOpen, model.PriorityUrgent)}, nil))
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u1", Ledger: []LedgerEntry{
		ledgerEntry("fp-ghsa", model.PriorityUrgent, model.StateOpen)}}))
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u2", Ledger: []LedgerEntry{
		ledgerEntry("fp-ghsa", model.PriorityHigh, model.StateOpen), ledgerEntry("fp-cve", model.PriorityLow, model.StateOpen)}}))

	require.NoError(t, st.RekeyFindings(ctx, []FindingRekey{{OldFingerprint: "fp-ghsa", NewFingerprint: "fp-cve", AdvisoryID: "CVE-X"}}))

	l, _ := st.Ledger(ctx, "u1", []string{"fp-cve"})
	assert.Equal(t, model.PriorityUrgent, l["fp-cve"].MaxPriority)
	l, _ = st.Ledger(ctx, "u1", []string{"fp-ghsa"})
	assert.Empty(t, l)
	l, _ = st.Ledger(ctx, "u2", []string{"fp-cve", "fp-ghsa"})
	require.Len(t, l, 1) // the existing u2/fp-cve row is replaced, not duplicated
	assert.Equal(t, model.PriorityHigh, l["fp-cve"].MaxPriority)
	fs, _ := st.FindingsByFingerprint(ctx, []string{"fp-cve", "fp-ghsa"})
	require.Len(t, fs, 1)
	assert.Equal(t, "CVE-X", fs["fp-cve"].AdvisoryID)
}

func TestStoreNotify_PruneAndMaxTransitionID(t *testing.T) {
	st := newStore(t)
	id, err := st.MaxTransitionID(ctx)
	require.NoError(t, err)
	assert.Zero(t, id)
	require.NoError(t, st.ApplyFindings(ctx, nil, []model.Transition{tr("fp-1", "", model.StateOpen), tr("fp-2", "", model.StateOpen)}))
	all, _ := st.TransitionsAfter(ctx, 0, 0)
	id, _ = st.MaxTransitionID(ctx)
	assert.Equal(t, all[1].ID, id)

	old := delivery("old-sent", t0)
	old.State = DeliverySent
	oldPending := delivery("old-pending", t0)
	recent := delivery("recent-sent", t0.Add(48*time.Hour))
	recent.State = DeliverySent
	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u1", Deliveries: []Delivery{old, oldPending, recent},
		Ledger: []LedgerEntry{ledgerEntry("resolved-old", model.PriorityHigh, model.StateResolved),
			ledgerEntry("open-old", model.PriorityHigh, model.StateOpen)}}))
	n, err := st.PruneNotify(ctx, t0.Add(24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	ds, _ := st.ListDeliveries(ctx, "u1", 0)
	assert.Len(t, ds, 2)
	assert.Equal(t, "recent-sent", ds[0].ID) // newest first
	l, _ := st.Ledger(ctx, "u1", []string{"resolved-old", "open-old"})
	assert.Len(t, l, 1)
	assert.Contains(t, l, "open-old")
}

func TestStoreNotify_NodesBaselineAt(t *testing.T) {
	st := newStore(t)
	t1 := t0.Add(time.Hour)
	require.NoError(t, st.PutNotifyTarget(ctx, "u1", "ops", "h1"))
	got, ok, err := st.NotifyTarget(ctx, "u1")
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, got.NodesBaselineAt.IsZero())

	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u1", NodesBaselineAt: t1}))
	got, _, err = st.NotifyTarget(ctx, "u1")
	require.NoError(t, err)
	require.True(t, got.NodesBaselineAt.Equal(t1))

	require.NoError(t, st.CommitNotify(ctx, NotifyCommit{Target: "u1", Cursors: map[string]int64{"notify:u1": 7}}))
	got, _, err = st.NotifyTarget(ctx, "u1")
	require.NoError(t, err)
	require.True(t, got.NodesBaselineAt.Equal(t1), "a zero NodesBaselineAt leaves it alone")
	all, err := st.NotifyTargets(ctx)
	require.NoError(t, err)
	require.True(t, all[0].NodesBaselineAt.Equal(t1))
}
