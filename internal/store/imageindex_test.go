package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestPlatformDigest(t *testing.T) {
	s := newStore(t)
	idx := "sha256:" + strings.Repeat("1", 64)
	mB := "sha256:" + strings.Repeat("b", 64)
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: mB, IndexDigest: idx, Repo: "docker.io/library/nginx",
		Platform: "linux/arm64", Status: model.ImagePending}))

	d, ok, err := s.PlatformDigest(ctx, idx, "linux/arm64")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, mB, d)

	_, ok, err = s.PlatformDigest(ctx, idx, "linux/amd64")
	require.NoError(t, err)
	require.False(t, ok)
}
