package store

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestUnmatchedImages(t *testing.T) {
	s := newStore(t)
	at := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	for _, img := range []model.Image{
		{Digest: "sha256:a", Status: model.ImageCatalogued},
		{Digest: "sha256:b", Status: model.ImageCatalogued},
		{Digest: "sha256:c", Status: model.ImagePending},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:b", at))
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:a", at.Add(time.Minute)))
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:c", at))    // not catalogued: not listed
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:gone", at)) // no image: dropped

	n, err := s.BeginMatch(ctx, "sha256:b")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = s.BeginMatch(ctx, "sha256:b")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	n, err = s.BeginMatch(ctx, "sha256:none")
	require.NoError(t, err)
	require.Zero(t, n)

	got, err := s.UnmatchedImages(ctx)
	require.NoError(t, err)
	require.Equal(t, []UnmatchedImage{{Digest: "sha256:b", Attempts: 2}, {Digest: "sha256:a"}}, got)

	require.NoError(t, s.MarkMatched(ctx, "sha256:b"))
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:a", at)) // catalogued again: attempts reset
	got, err = s.UnmatchedImages(ctx)
	require.NoError(t, err)
	require.Equal(t, []UnmatchedImage{{Digest: "sha256:a"}}, got)
}

func TestAcquisitionsInflight(t *testing.T) {
	s := newStore(t)
	at := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	stale, err := s.BeginAcquire(ctx, "sha256:a", at)
	require.NoError(t, err)
	require.False(t, stale)
	// Never ended: the next begin finds the previous attempt.
	stale, err = s.BeginAcquire(ctx, "sha256:a", at.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, stale)
	require.NoError(t, s.EndAcquire(ctx, "sha256:a"))
	stale, err = s.BeginAcquire(ctx, "sha256:a", at)
	require.NoError(t, err)
	require.False(t, stale)
}

func TestOwnersOfExpiredQuarantine(t *testing.T) {
	s := newStore(t)
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	for _, img := range []model.Image{
		{Digest: "sha256:failed-expired", Status: model.ImageCatalogFailed, QuarantinedUntil: now.Add(-time.Second)},
		{Digest: "sha256:failed-current", Status: model.ImageCatalogFailed, QuarantinedUntil: now.Add(time.Hour)},
		{Digest: "unknown:x:1", Status: model.ImageUnresolvable, QuarantinedUntil: now},
		{Digest: "sha256:ok", Status: model.ImageCatalogued},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	for key, digest := range map[string]string{
		"Deployment/a/x": "sha256:failed-expired", "Deployment/a/y": "sha256:failed-current",
		"CronJob/b/z": "unknown:x:1", "Deployment/c/w": "sha256:ok",
	} {
		parts := strings.SplitN(key, "/", 3)
		require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: parts[0], Namespace: parts[1], Name: parts[2]},
			Containers: []model.ContainerUse{{Name: "app", Digest: digest}}}))
	}
	got, err := s.OwnersOfExpiredQuarantine(ctx, now)
	require.NoError(t, err)
	require.Equal(t, []string{"CronJob/b/z", "Deployment/a/x"}, got)
}
