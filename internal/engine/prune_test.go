package engine_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// Prune bounds the history of a long-lived open finding (F76): transitions older than the
// retention window go, except its latest store.TransitionsKept.
func TestEngine_PruneBoundsTheHistoryOfOpenFindings(t *testing.T) {
	h := newHarness(t)
	h.catalogueAPI()
	f := h.finding(apiKey, cve)
	old := t0.Add(-200 * 24 * time.Hour)
	var announcements []model.Transition
	for i := range 40 {
		announcements = append(announcements, model.Transition{Fingerprint: f.Fingerprint, Owner: f.Owner, AdvisoryID: cve,
			FromState: model.StateOpen, ToState: model.StateOpen, FromPriority: f.Priority, ToPriority: f.Priority,
			Trigger: model.TriggerUpgradeAvailable, At: old.Add(time.Duration(i) * 24 * time.Hour)})
	}
	require.NoError(t, h.st.ApplyFindings(ctx, nil, announcements))
	require.Len(t, h.transitions(), 41)

	_, err := h.e.Prune(ctx)
	require.NoError(t, err)
	ts := h.transitions()
	require.Len(t, ts, store.TransitionsKept+1, "the 20 latest, and the creation inside the window")
	require.Equal(t, model.FindingState(""), ts[0].FromState, "the creation, at t0, is inside the window")
	require.Equal(t, old.Add(20*24*time.Hour), ts[1].At, "the oldest of the 20 latest announcements")
}
