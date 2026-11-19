package eol

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx = context.Background()
	now = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
)

func day(y int, m time.Month, d int) *time.Time {
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return &t
}

func newEvaluator(t *testing.T, cycles ...store.EOLCycle) *Evaluator {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	require.NoError(t, st.ReplaceEOL(ctx, cycles))
	e := New(st, func() time.Time { return now })
	require.NoError(t, e.Reload(ctx))
	return e
}

func seeded(t *testing.T) *Evaluator {
	return newEvaluator(t,
		store.EOLCycle{Product: "kubernetes", Cycle: "1.35", EOLDate: day(2027, 2, 28), Latest: "1.35.10"},
		store.EOLCycle{Product: "kubernetes", Cycle: "1.34", EOLDate: day(2026, 10, 27), IsEOL: true, Latest: "1.34.13"},
		store.EOLCycle{Product: "kubernetes", Cycle: "1.31", EOLDate: day(2025, 11, 11), IsEOL: true},
		store.EOLCycle{Product: "ubuntu", Cycle: "24.04", EOLDate: day(2029, 4, 25)},
		store.EOLCycle{Product: "alpine-linux", Cycle: "3.20", EOLDate: day(2026, 4, 1), IsEOL: true},
		store.EOLCycle{Product: "nodejs", Cycle: "22", EOLDate: day(2027, 4, 30)},
		store.EOLCycle{Product: "debian", Cycle: "12", Codename: "Bookworm", EOLDate: day(2028, 6, 30)},
		store.EOLCycle{Product: "debian", Cycle: "11", EOLDate: day(2026, 11, 1)},
		store.EOLCycle{Product: "go", Cycle: "1.25"},
	)
}

func TestEvaluate_LongestCyclePrefix(t *testing.T) {
	e := seeded(t)
	for _, tc := range []struct{ product, version, cycle string }{
		{"kubernetes", "1.35.1", "1.35"}, {"ubuntu", "24.04.4", "24.04"}, {"alpine-linux", "3.20.3", "3.20"},
		{"nodejs", "22.11.0", "22"}, {"debian", "12", "12"}, {"go", "v1.25.3", "1.25"},
	} {
		s, ok := e.Evaluate(tc.product, tc.version)
		require.True(t, ok, tc.product)
		require.Equal(t, tc.cycle, s.Cycle, tc.product)
		require.Equal(t, tc.product, s.Product)
	}
}

func TestEvaluate_EOLByDate(t *testing.T) {
	e := seeded(t)
	s, ok := e.Evaluate("kubernetes", "1.34.2")
	require.True(t, ok)
	require.True(t, s.IsEOL)
	require.Equal(t, *day(2026, 10, 27), *s.EOLDate)
	require.Equal(t, "1.34.13", s.Latest)
	s, _ = e.Evaluate("debian", "12")
	require.False(t, s.IsEOL)
	s, _ = e.Evaluate("debian", "11") // stored not-EOL, but the date has passed
	require.True(t, s.IsEOL)
}

func TestEvaluate_Overrides(t *testing.T) {
	e := seeded(t)
	s, ok := e.Evaluate("k3s", "1.31.4")
	require.True(t, ok)
	require.Equal(t, Status{Product: "k3s", Cycle: "1.31", IsEOL: true, EOLDate: day(2025, 11, 11)}, s)
	s, _ = e.Evaluate("rke2", "1.35.1")
	require.Equal(t, "1.35", s.Cycle)
	s, ok = e.Evaluate("distroless", "12")
	require.True(t, ok)
	require.Equal(t, Status{Product: "distroless", Cycle: "12", EOLDate: day(2028, 6, 30)}, s)
	for _, tc := range []struct{ product, version, cycle, note string }{
		{"wolfi", "20260101", "rolling", "rolling release"},
		{"flatcar", "4230.2.3", "rolling", "rolling release"},
		{"bottlerocket", "1.30.0", "1.30", "lifecycle follows the variant's Kubernetes version"},
		{"talos", "1.9.1", "1.9", "security updates for the two latest minor releases"},
	} {
		s, ok := e.Evaluate(tc.product, tc.version)
		require.True(t, ok, tc.product)
		require.Equal(t, tc.cycle, s.Cycle, tc.product)
		require.Equal(t, tc.note, s.Note, tc.product)
		require.False(t, s.IsEOL)
	}
	_, ok = e.Evaluate("nosuch", "1")
	require.False(t, ok)
}

func TestText(t *testing.T) {
	d := func(y int, m time.Month, dd int) *time.Time { return day(y, m, dd) }
	require.Equal(t, "debian 10 reached end of life 2024-06-30", Text(Status{Product: "debian", Cycle: "10", IsEOL: true, EOLDate: d(2024, 6, 30)}, now))
	require.Equal(t, "debian 10 reached end of life", Text(Status{Product: "debian", Cycle: "10", IsEOL: true}, now))
	require.Equal(t, "containerd 2.0 reaches end of life 2027-01-15", Text(Status{Product: "containerd", Cycle: "2.0", EOLDate: d(2027, 1, 15)}, d(2026, 12, 1).UTC()))
	require.Empty(t, Text(Status{Product: "debian", Cycle: "12", EOLDate: d(2028, 6, 30)}, now))
	require.Empty(t, Text(Status{Product: "wolfi", Cycle: "rolling", Note: "rolling release"}, now))
	require.Equal(t, "a 1 reached end of life; b 2 reached end of life", JoinText([]Status{
		{Product: "a", Cycle: "1", IsEOL: true}, {Product: "wolfi", Cycle: "rolling"}, {Product: "b", Cycle: "2", IsEOL: true},
	}, now))
}
