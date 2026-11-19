package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGrypeDBBuilds_DedupAndOrder(t *testing.T) {
	s := newStore(t)
	b1, b2 := t0.Add(time.Hour), t0.Add(2*time.Hour)
	for _, b := range []time.Time{b2, b1, b2} {
		require.NoError(t, s.RecordGrypeDBBuild(ctx, b))
	}
	got, err := s.GrypeDBBuilds(ctx)
	require.NoError(t, err)
	require.Equal(t, []time.Time{b1, b2}, got)

	var later []time.Time
	for i := 1; i <= 35; i++ {
		b := b2.Add(time.Duration(i) * 24 * time.Hour)
		later = append(later, b)
		require.NoError(t, s.RecordGrypeDBBuild(ctx, b))
	}
	got, err = s.GrypeDBBuilds(ctx)
	require.NoError(t, err)
	require.Equal(t, later[5:], got, "only the 30 newest builds are kept")

	require.Error(t, s.RecordGrypeDBBuild(ctx, time.Time{}))
}
