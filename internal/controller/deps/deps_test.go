package deps

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHooks_FeedStaleFansOut(t *testing.T) {
	type call struct {
		feed       string
		last       time.Time
		staleAfter time.Duration
	}
	var h Hooks
	var a, b []call
	h.OnFeedStale(func(feed string, last time.Time, staleAfter time.Duration) {
		a = append(a, call{feed, last, staleAfter})
	})
	h.OnFeedStale(func(feed string, last time.Time, staleAfter time.Duration) {
		b = append(b, call{feed, last, staleAfter})
	})

	at := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	h.FeedStale("osv", at, 2*time.Hour)

	want := []call{{"osv", at, 2 * time.Hour}}
	require.Equal(t, want, a)
	require.Equal(t, want, b)
}
