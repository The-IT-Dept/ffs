package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

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
		return newReady(func() bool { return synced }, func() sbom.AcquirerStats { return stats }, func() bool { return idle }, grypeOK)
	}

	t.Run("grypedb disabled", func(t *testing.T) {
		synced, idle, stats = false, true, sbom.AcquirerStats{}
		ready := fakes(grypeReady(false, nil))
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
		ready := fakes(grypeReady(true, st))
		require.False(t, ready(ctx), "grypedb never synced")

		require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: feeds.NameGrypeDB, LastAttempt: time.Now()}))
		require.False(t, ready(ctx), "grypedb attempted but never succeeded")

		now := time.Now()
		require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: feeds.NameGrypeDB, LastAttempt: now, LastSuccess: now}))
		require.True(t, ready(ctx))

		stats = sbom.AcquirerStats{Queued: 1}
		require.True(t, ready(ctx), "readiness is sticky")
	})
}

func TestWire_OSVGitRepos(t *testing.T) {
	repos := osvGitRepos()
	require.Contains(t, repos, "github.com/php/php-src")
	require.Contains(t, repos, "github.com/kubernetes/kubernetes")
}
