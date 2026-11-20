package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/store"
)

// nopSink accepts every message; the test reads the queued deliveries, not what is sent.
type nopSink struct{}

func (nopSink) Type() string                               { return "webhook" }
func (nopSink) Send(context.Context, notify.Message) error { return nil }

// immediateDeliveries returns the immediate deliveries queued for the target uid.
func immediateDeliveries(t *testing.T, st *store.Store, uid string) []store.Delivery {
	t.Helper()
	ds, err := st.ListDeliveries(ctx, uid, 100)
	require.NoError(t, err)
	var out []store.Delivery
	for _, d := range ds {
		if d.Kind == string(notify.KindImmediate) {
			out = append(out, d)
		}
	}
	return out
}

// A provisional (OSV-first) high finding is held back from immediate alerts (spec §6.5). Once a
// Grype DB confirms it at the same priority, the confirmation is a transition of its own, and the
// notify classifier sends it immediately, since nothing was sent for it before (F57).
func TestEngine_ConfirmedProvisionalFindingAlertsImmediately(t *testing.T) {
	h := newHarness(t)
	const uid = "uid-oncall"
	ne := notify.New(h.st.Store, notify.Options{Cluster: "prod", Now: h.clock.Now})
	require.NoError(t, ne.Register(ctx, notify.TargetConfig{UID: uid, Name: "oncall", Type: "webhook",
		ImmediateMin: model.PriorityHigh, Digest: notify.DigestConfig{Schedule: "0 9 1 1 *"}}, nopSink{}))
	require.NoError(t, ne.ProcessOnce(ctx)) // the baseline, before any finding exists

	// OSV alone matches: a provisional high finding (critical by its CNA, with a fix).
	h.osv.fn = matchOn(nil, d1, newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1"))
	require.NoError(t, h.e.OnImageCatalogued(ctx, d1))
	require.NoError(t, h.e.Drain(ctx))
	f := h.finding(apiKey, cve)
	require.True(t, f.Provisional)
	require.Equal(t, model.PriorityHigh, f.Priority)
	require.NoError(t, ne.ProcessOnce(ctx))
	require.Empty(t, immediateDeliveries(t, h.st.Store, uid), "a provisional high finding waits for the digest")

	// A Grype DB built after the OSV observation confirms it at the same priority.
	h.clock.now = t0.Add(2 * time.Hour)
	h.grype.fn = matchOn(nil, d1, h.grypeOn(h.libssl3))
	require.NoError(t, h.e.OnGrypeDB(ctx, grypedb.Update{Path: "db", Built: t0.Add(time.Hour), Full: true}))
	require.NoError(t, h.e.Drain(ctx))
	f = h.finding(apiKey, cve)
	require.False(t, f.Provisional)
	require.Equal(t, model.PriorityHigh, f.Priority)

	ts := h.transitions()
	last := ts[len(ts)-1]
	require.Equal(t, model.Transition{ID: last.ID, Fingerprint: f.Fingerprint, Owner: apiRef, AdvisoryID: cve,
		FromState: model.StateOpen, ToState: model.StateOpen, FromPriority: model.PriorityHigh, ToPriority: model.PriorityHigh,
		Trigger: model.TriggerNewAdvisory, Provisional: false, At: h.clock.now}, last,
		"the confirmation carries NewAdvisory, the closest trigger the enum has")

	require.NoError(t, ne.ProcessOnce(ctx))
	ds := immediateDeliveries(t, h.st.Store, uid)
	require.Len(t, ds, 1, "the confirmed finding is alerted immediately")
	require.Contains(t, string(ds[0].Payload), cve)

	// Confirmed again by the next DB: nothing changes, nothing more is sent.
	h.clock.now = t0.Add(26 * time.Hour)
	require.NoError(t, h.e.OnGrypeDB(ctx, grypedb.Update{Path: "db2", Built: t0.Add(25 * time.Hour), Full: true}))
	require.NoError(t, h.e.Drain(ctx))
	require.Len(t, h.transitions(), len(ts))
	require.NoError(t, ne.ProcessOnce(ctx))
	require.Len(t, immediateDeliveries(t, h.st.Store, uid), 1)
}
