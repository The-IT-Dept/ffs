package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

func TestReady_StickyAndGrypeOptional(t *testing.T) {
	ctx := context.Background()
	var (
		synced, idle bool
		stats        sbom.AcquirerStats
	)
	fakes := func(grypeOK func(context.Context) bool) func(context.Context) bool {
		return newReady(readyOptions{Synced: func() bool { return synced }, Stats: func() sbom.AcquirerStats { return stats },
			Idle: func() bool { return idle }, GrypeOK: grypeOK, Wait: time.Hour, Log: logr.Discard()})
	}

	t.Run("grypedb disabled", func(t *testing.T) {
		synced, idle, stats = false, true, sbom.AcquirerStats{}
		ready := fakes(grypeReady(false, nil, logr.Discard()))
		require.False(t, ready(ctx), "inventory not synced")

		synced, stats = true, sbom.AcquirerStats{Queued: 1}
		require.False(t, ready(ctx), "acquirer queue not empty")

		stats = sbom.AcquirerStats{InFlight: 1}
		require.False(t, ready(ctx), "acquisition in flight")

		stats, idle = sbom.AcquirerStats{}, false
		require.False(t, ready(ctx), "engine busy")

		idle = true
		require.True(t, ready(ctx))

		stats, idle = sbom.AcquirerStats{Queued: 3, InFlight: 1}, false
		require.True(t, ready(ctx), "readiness is sticky")
	})

	t.Run("grypedb enabled", func(t *testing.T) {
		st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, st.Close()) })

		synced, idle, stats = true, true, sbom.AcquirerStats{}
		ready := fakes(grypeReady(true, st, logr.Discard()))
		require.False(t, ready(ctx), "grypedb never synced")

		require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: feeds.NameGrypeDB, LastAttempt: time.Now()}))
		require.False(t, ready(ctx), "grypedb attempted but never succeeded, within the wait")

		now := time.Now()
		require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: feeds.NameGrypeDB, LastAttempt: now, LastSuccess: now}))
		require.True(t, ready(ctx))

		stats = sbom.AcquirerStats{Queued: 1}
		require.True(t, ready(ctx), "readiness is sticky")
	})
}

// TestReady_BoundedWait pins that readiness never waits for good (F5): a Grype DB that keeps
// failing, an engine that never goes idle or a queue that never drains hold notifications back for
// at most the wait after the inventory synced. An unsynced inventory still holds them back.
func TestReady_BoundedWait(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	start := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: feeds.NameGrypeDB, LastAttempt: start,
		LastError: "download https://grype.anchore.io: connection refused"}))

	cases := map[string]struct {
		idle  bool
		stats sbom.AcquirerStats
		grype func(context.Context) bool
	}{
		"grypedb keeps failing": {idle: true, grype: grypeReady(true, st, logr.Discard())},
		"engine never idle":     {idle: false, grype: grypeReady(false, nil, logr.Discard())},
		"queue never drains":    {idle: true, stats: sbom.AcquirerStats{Queued: 1}, grype: grypeReady(false, nil, logr.Discard())},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			now, synced := start, false
			ready := newReady(readyOptions{Synced: func() bool { return synced }, Stats: func() sbom.AcquirerStats { return c.stats },
				Idle: func() bool { return c.idle }, GrypeOK: c.grype, Wait: time.Hour, Now: func() time.Time { return now },
				Log: logr.Discard()})

			now = start.Add(3 * time.Hour)
			require.False(t, ready(ctx), "the wait starts once the inventory has synced")
			synced = true
			require.False(t, ready(ctx))
			now = now.Add(59 * time.Minute)
			require.False(t, ready(ctx))
			now = now.Add(time.Minute)
			require.True(t, ready(ctx), "ready once the wait has passed")
			require.True(t, ready(ctx), "and for good")
		})
	}
}

// TestReady_WaitsWhileCatalogueProgresses (R3): the wait is a liveness fallback, not a deadline. A
// large first catalogue that is still making progress when the wait has passed holds notifications
// back until it has finished, so the baseline covers every image rather than those catalogued in
// the first hour.
func TestReady_WaitsWhileCatalogueProgresses(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	now, stats := start, sbom.AcquirerStats{Queued: 20, InFlight: 2}
	ready := newReady(readyOptions{Synced: func() bool { return true }, Stats: func() sbom.AcquirerStats { return stats },
		Idle: func() bool { return true }, GrypeOK: grypeReady(false, nil, logr.Discard()), Wait: time.Hour,
		Now: func() time.Time { return now }, Log: logr.Discard()})
	require.False(t, ready(ctx))

	// Two images catalogued every ten minutes, for well over the wait.
	for stats.Queued > 0 {
		now = now.Add(10 * time.Minute)
		stats.Queued -= 2
		stats.Catalogued += 2
		require.False(t, ready(ctx), "cataloguing still progressing after %s", now.Sub(start))
	}
	now = now.Add(10 * time.Minute)
	stats.InFlight, stats.Failed = 0, 2
	require.True(t, ready(ctx), "ready once the catalogue has finished")
}

// TestReady_StallAfterTheWait (R3): once the wait has passed, a catalogue that stops making progress
// is given up on after the stall time, counted from its last outcome; an image waiting out a retry
// delay is still work to wait for.
func TestReady_StallAfterTheWait(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	now, stats := start, sbom.AcquirerStats{Queued: 10, InFlight: 2}
	ready := newReady(readyOptions{Synced: func() bool { return true }, Stats: func() sbom.AcquirerStats { return stats },
		Idle: func() bool { return true }, GrypeOK: grypeReady(false, nil, logr.Discard()), Wait: time.Hour,
		Stall: 30 * time.Minute, Now: func() time.Time { return now }, Log: logr.Discard()})
	require.False(t, ready(ctx))

	// Progress until 70 minutes in, then the registry stops answering: the rest wait out retries.
	now, stats.Queued, stats.Catalogued = start.Add(70*time.Minute), 4, 6
	require.False(t, ready(ctx))
	now, stats.Queued, stats.InFlight, stats.Retrying = start.Add(80*time.Minute), 0, 0, 6
	require.False(t, ready(ctx), "nothing queued or in flight, but images wait to retry")
	now = start.Add(99 * time.Minute)
	require.False(t, ready(ctx), "29 minutes without progress")
	now = start.Add(100 * time.Minute)
	require.True(t, ready(ctx), "30 minutes without progress after the wait")
}

func TestWire_OSVGitRepos(t *testing.T) {
	repos := osvGitRepos()
	require.Contains(t, repos, "github.com/php/php-src")
	require.Contains(t, repos, "github.com/kubernetes/kubernetes")
}
