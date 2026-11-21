package engine_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
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

// failingPrunes fails the prune steps named in fail, as a busy or timed-out delete would, and runs
// the others on the store.
type failingPrunes struct {
	engine.Store
	fail map[string]error
}

func (f *failingPrunes) PruneResolved(ctx context.Context, olderThan time.Time) (int, error) {
	if err := f.fail["resolved"]; err != nil {
		return 0, err
	}
	return f.Store.PruneResolved(ctx, olderThan)
}

func (f *failingPrunes) PruneTransitions(ctx context.Context, olderThan time.Time, keep int) (int, error) {
	if err := f.fail["transitions"]; err != nil {
		return 0, err
	}
	return f.Store.PruneTransitions(ctx, olderThan, keep)
}

// TestEngine_PruneRunsEveryStep (W22): a prune step that keeps failing never stops the others, so
// unused images are still pruned while the transitions delete fails; the errors come back together,
// with the count of the resolved findings that were deleted.
func TestEngine_PruneRunsEveryStep(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.st.DeleteOwner(ctx, cartKey)) // d2 falls out of use
	f := &failingPrunes{Store: h.st, fail: map[string]error{}}
	e := engine.New(engine.Options{Config: config.Default(), Store: f, Grype: h.grype, Now: h.clock.Now})
	_, err := e.Prune(ctx) // marks d2 unused
	require.NoError(t, err)

	h.clock.now = t0.Add(8 * 24 * time.Hour)
	at := h.clock.now.Add(-2161 * time.Hour)
	require.NoError(t, h.st.ApplyFindings(ctx, []model.Finding{{Fingerprint: "fp-old", Owner: apiRef, ImageRepo: apiRepo,
		AdvisoryID: "CVE-2026-1000", State: model.StateResolved, ResolvedAt: &at}}, nil))
	busy, timeout := errors.New("database is locked"), errors.New("context deadline exceeded")
	f.fail["transitions"] = busy
	n, err := e.Prune(ctx)
	require.ErrorIs(t, err, busy)
	require.Equal(t, 1, n, "the resolved finding past retention is deleted and counted")
	_, ok, gerr := h.st.GetImage(ctx, d2)
	require.NoError(t, gerr)
	require.False(t, ok, "the unused image is pruned although the transitions step failed")

	f.fail["resolved"] = timeout
	_, err = e.Prune(ctx)
	require.ErrorIs(t, err, busy)
	require.ErrorIs(t, err, timeout, "every failing step is reported")
}
