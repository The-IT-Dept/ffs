package osvrange_test

import (
	"cmp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/match/osvrange"
)

// compareInts compares versions that are plain integers. It fails the test when given "0", which
// these tests only use as an introduced event, and anything that is not an integer.
func compareInts(t *testing.T) func(a, b string) int {
	t.Helper()
	atoi := func(s string) int {
		require.NotEqual(t, "0", s, "compare called with an introduced 0")
		n, err := strconv.Atoi(s)
		require.NoError(t, err)
		return n
	}
	return func(a, b string) int { return cmp.Compare(atoi(a), atoi(b)) }
}

func intro(v string) osvrange.Event { return osvrange.Event{Introduced: v} }
func fixed(v string) osvrange.Event { return osvrange.Event{Fixed: v} }
func last(v string) osvrange.Event  { return osvrange.Event{LastAffected: v} }

func TestOSVRange_Walk(t *testing.T) {
	// two intervals, given out of order: [0, 5) and [7, 9)
	events := []osvrange.Event{fixed("9"), intro("7"), intro("0"), fixed("5")}
	for _, tc := range []struct {
		version string
		want    osvrange.Result
	}{
		{"1", osvrange.Result{Affected: true, Fixed: []string{"5"}}},
		{"4", osvrange.Result{Affected: true, Fixed: []string{"5"}}},
		{"5", osvrange.Result{Fixed: []string{"9"}}},
		{"6", osvrange.Result{Fixed: []string{"9"}}},
		{"7", osvrange.Result{Affected: true, Fixed: []string{"9"}}},
		{"8", osvrange.Result{Affected: true, Fixed: []string{"9"}}},
		{"9", osvrange.Result{}},
		{"12", osvrange.Result{}},
	} {
		require.Equal(t, tc.want, osvrange.Evaluate(events, compareInts(t), tc.version), "version %s", tc.version)
	}
}

func TestOSVRange_LastAffected(t *testing.T) {
	events := []osvrange.Event{intro("0"), last("3"), intro("6"), fixed("8")}
	cmpFn := compareInts(t)

	require.Equal(t, osvrange.Result{Affected: true, Fixed: []string{"8"}, EndsInLastAffected: true},
		osvrange.Evaluate(events, cmpFn, "3"))
	require.Equal(t, osvrange.Result{Fixed: []string{"8"}}, osvrange.Evaluate(events, cmpFn, "4"))
	require.Equal(t, osvrange.Result{Affected: true, Fixed: []string{"8"}}, osvrange.Evaluate(events, cmpFn, "7"))

	open := []osvrange.Event{intro("2")}
	require.Equal(t, osvrange.Result{Affected: true}, osvrange.Evaluate(open, cmpFn, "100"))
	require.Equal(t, osvrange.Result{}, osvrange.Evaluate(open, cmpFn, "1"))
}

func TestOSVRange_EmptyEventsIgnored(t *testing.T) {
	events := []osvrange.Event{{}, intro("1"), {}, fixed("2")}
	require.Equal(t, osvrange.Result{Affected: true, Fixed: []string{"2"}}, osvrange.Evaluate(events, compareInts(t), "1"))
	require.Equal(t, osvrange.Result{}, osvrange.Evaluate(nil, compareInts(t), "1"))
}
