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

func TestWire_OSVGitRepos(t *testing.T) {
	repos := osvGitRepos()
	require.Contains(t, repos, "github.com/php/php-src")
	require.Contains(t, repos, "github.com/kubernetes/kubernetes")
}
