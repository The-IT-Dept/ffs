package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStore_ReplaceEOLRoundTrip(t *testing.T) {
	s := newStore(t)
	d := time.Date(2028, 6, 30, 0, 0, 0, 0, time.UTC)
	rel := time.Date(2023, 6, 10, 0, 0, 0, 0, time.UTC)
	first := []EOLCycle{
		{Product: "go", Cycle: "1.26", ReleaseDate: rel, Latest: "1.26.1", LatestDate: rel},
		{Product: "debian", Cycle: "12", Codename: "Bookworm", ReleaseDate: rel, EOLDate: &d, IsEOL: false, Latest: "12.5", LatestDate: rel},
		{Product: "debian", Cycle: "10", EOLDate: &d, IsEOL: true},
	}
	require.NoError(t, s.ReplaceEOL(ctx, first))
	got, err := s.ListEOL(ctx)
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, "10", got[0].Cycle)
	require.Equal(t, "12", got[1].Cycle)
	require.Equal(t, "Bookworm", got[1].Codename)
	require.Equal(t, d, *got[1].EOLDate)
	require.Equal(t, rel, got[1].ReleaseDate)
	require.True(t, got[0].IsEOL)
	require.Equal(t, "go", got[2].Product)
	require.Nil(t, got[2].EOLDate)
	require.Equal(t, "1.26.1", got[2].Latest)

	require.NoError(t, s.ReplaceEOL(ctx, first[:1]))
	got, err = s.ListEOL(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "go", got[0].Product)
}
