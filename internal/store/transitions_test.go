package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestPruneTransitions_KeepsTheLatestAndTheRecent(t *testing.T) {
	s := newStore(t)
	cutoff := t0.Add(-90 * 24 * time.Hour)
	// history appends n transitions of fp, the first old ones before the cutoff, one hour apart.
	history := func(fp string, old, recent int) {
		var ts []model.Transition
		for i := range old + recent {
			x := tr(fp, model.StateOpen, model.StateOpen)
			x.Trigger = model.TriggerUpgradeAvailable
			x.At = cutoff.Add(time.Duration(i-old) * time.Hour)
			if i >= old {
				x.At = cutoff.Add(time.Duration(i-old+1) * time.Hour)
			}
			ts = append(ts, x)
		}
		require.NoError(t, s.ApplyFindings(ctx, []model.Finding{fd(fp, model.StateOpen, model.PriorityHigh)}, ts))
	}
	history("fp-flapping", 30, 5) // 35: the 15 newest old ones and the 5 recent stay, 15 go
	history("fp-quiet", 12, 0)    // 12 old ones: within the 20 kept
	history("fp-busy", 0, 25)     // 25 recent ones: inside the window
	history("fp-edge", 21, 0)     // 21 old ones: the oldest goes
	all, err := s.TransitionsAfter(ctx, 0, 1000)
	require.NoError(t, err)
	before := map[string][]int64{}
	for _, x := range all {
		before[x.Fingerprint] = append(before[x.Fingerprint], x.ID)
	}

	n, err := s.PruneTransitions(ctx, cutoff, TransitionsKept)
	require.NoError(t, err)
	require.Equal(t, 15+1, n)

	left, err := s.TransitionsAfter(ctx, 0, 1000)
	require.NoError(t, err)
	after := map[string][]int64{}
	for _, x := range left {
		after[x.Fingerprint] = append(after[x.Fingerprint], x.ID)
	}
	require.Equal(t, before["fp-flapping"][15:], after["fp-flapping"], "the latest 20 stay")
	require.Equal(t, before["fp-quiet"], after["fp-quiet"])
	require.Equal(t, before["fp-busy"], after["fp-busy"], "transitions inside the window stay")
	require.Equal(t, before["fp-edge"][1:], after["fp-edge"])

	n, err = s.PruneTransitions(ctx, cutoff, TransitionsKept)
	require.NoError(t, err)
	require.Zero(t, n, "a second prune finds nothing")
	n, err = s.PruneTransitions(ctx, time.Time{}, TransitionsKept)
	require.NoError(t, err)
	require.Zero(t, n)
}
