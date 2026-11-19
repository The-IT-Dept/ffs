package inventory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

var (
	ctx = context.Background()
	idx = "sha256:" + strings.Repeat("1", 64)
	mA  = "sha256:" + strings.Repeat("a", 64)
	mB  = "sha256:" + strings.Repeat("b", 64)
	cfg = "sha256:" + strings.Repeat("c", 64)
)

type fakeResolver struct {
	tags          map[string]string
	platforms     map[string]registry.Manifest
	configs       map[string]string
	err           error
	platformCalls int
}

func (f *fakeResolver) ResolveTag(_ context.Context, repo, tag string, _ registry.CredSet) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	d, ok := f.tags[repo+":"+tag]
	if !ok {
		return "", registry.ErrNotFound
	}
	return d, nil
}

func (f *fakeResolver) PlatformManifest(_ context.Context, repo, digest, platform string, _ registry.CredSet) (registry.Manifest, error) {
	f.platformCalls++
	if f.err != nil {
		return registry.Manifest{}, f.err
	}
	m, ok := f.platforms[digest+"|"+platform]
	if !ok {
		return registry.Manifest{}, registry.ErrNotFound
	}
	return m, nil
}

func (f *fakeResolver) ConfigDigest(_ context.Context, _, digest string, _ registry.CredSet) (string, error) {
	return f.configs[digest], nil
}

type emptyLookup struct{}

func (emptyLookup) GetImage(context.Context, string) (model.Image, bool, error) {
	return model.Image{}, false, nil
}

func (emptyLookup) PlatformDigest(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

type mapLookup struct {
	platforms map[string]string
	images    map[string]model.Image
}

func (m mapLookup) GetImage(_ context.Context, d string) (model.Image, bool, error) {
	i, ok := m.images[d]
	return i, ok, nil
}

func (m mapLookup) PlatformDigest(_ context.Context, ix, p string) (string, bool, error) {
	d, ok := m.platforms[ix+"|"+p]
	return d, ok, nil
}

func TestNormalizeRepo(t *testing.T) {
	for in, want := range map[string]string{
		"nginx": "docker.io/library/nginx", "nginx:1.27": "docker.io/library/nginx",
		"docker.io/nginx": "docker.io/library/nginx", "index.docker.io/library/nginx@" + mA: "docker.io/library/nginx",
		"registry-1.docker.io/bitnami/redis": "docker.io/bitnami/redis",
		"ghcr.io/the-it-dept/ffs:v0.0.1":     "ghcr.io/the-it-dept/ffs", "localhost:5000/app": "localhost:5000/app",
	} {
		got, err := NormalizeRepo(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
}

func TestParseImageID(t *testing.T) {
	for _, c := range []struct {
		in, repo, digest string
		bare             bool
	}{
		{"docker.io/library/nginx@" + mA, "docker.io/library/nginx", mA, false},
		{"docker-pullable://nginx@" + mA, "docker.io/library/nginx", mA, false},
		{cfg, "", cfg, true},
		{strings.Repeat("c", 64), "", cfg, true},
		{"docker://" + cfg, "", cfg, true},
	} {
		repo, d, bare, err := ParseImageID(c.in)
		require.NoError(t, err, c.in)
		require.Equal(t, c.repo, repo, c.in)
		require.Equal(t, c.digest, d, c.in)
		require.Equal(t, c.bare, bare, c.in)
	}
	for _, in := range []string{"", "nginx:latest"} {
		_, _, _, err := ParseImageID(in)
		require.Error(t, err, in)
	}
}

func TestNormalize_BareConfigDigestIsUnresolvable(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	fr := &fakeResolver{
		tags:      map[string]string{"docker.io/library/nginx:1.27": idx},
		platforms: map[string]registry.Manifest{idx + "|linux/amd64": {Digest: mA, IndexDigest: idx, Platform: "linux/amd64"}},
		configs:   map[string]string{mA: "sha256:" + strings.Repeat("9", 64)},
	}
	n := NewNormalizer(fr, emptyLookup{}, func() time.Time { return now })
	amd64 := NodePlatform{OS: "linux", Arch: "amd64"}

	img, err := n.Normalize(ctx, ContainerImage{Image: "docker.io/library/nginx:1.27", ImageID: cfg, Node: amd64})
	require.NoError(t, err)
	require.Equal(t, model.ImageUnresolvable, img.Status)
	require.Equal(t, cfg, img.Digest)
	require.Equal(t, fmt.Sprintf(ReasonSideLoadedMismatch, "docker.io/library/nginx", "1.27"), img.StatusReason)
	require.True(t, img.QuarantinedUntil.Equal(now.Add(6*time.Hour)))

	img, err = n.Normalize(ctx, ContainerImage{Image: cfg, ImageID: cfg, Node: amd64})
	require.NoError(t, err)
	require.Equal(t, model.ImageUnresolvable, img.Status)
	require.Equal(t, ReasonSideLoadedNoTag, img.StatusReason)

	fr.configs[mA] = cfg
	img, err = n.Normalize(ctx, ContainerImage{Image: "docker.io/library/nginx:1.27", ImageID: cfg, Node: amd64})
	require.NoError(t, err)
	require.Equal(t, model.ImagePending, img.Status)
	require.Equal(t, mA, img.Digest)
	require.Equal(t, idx, img.IndexDigest)
}

func TestNormalize_IndexDigestResolvedPerNodeArch(t *testing.T) {
	fr := &fakeResolver{platforms: map[string]registry.Manifest{
		idx + "|linux/amd64": {Digest: mA, IndexDigest: idx, Platform: "linux/amd64", Annotations: map[string]string{registry.AnnotationVersion: "1.27.3"}},
		idx + "|linux/arm64": {Digest: mB, IndexDigest: idx, Platform: "linux/arm64"},
	}}
	now := func() time.Time { return time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC) }
	const repo = "docker.io/library/nginx"
	id := repo + "@" + idx
	amd64, arm64 := NodePlatform{OS: "linux", Arch: "amd64"}, NodePlatform{OS: "linux", Arch: "arm64", Variant: "v8"}
	n := NewNormalizer(fr, emptyLookup{}, now)

	img, err := n.Normalize(ctx, ContainerImage{Image: repo + ":1.27", ImageID: id, Node: amd64})
	require.NoError(t, err)
	require.Equal(t, model.Image{Digest: mA, IndexDigest: idx, Repo: repo, Platform: "linux/amd64",
		VersionAnnotation: "1.27.3", Status: model.ImagePending}, img)

	img, err = n.Normalize(ctx, ContainerImage{Image: repo + ":1.27", ImageID: id, Node: arm64})
	require.NoError(t, err)
	require.Equal(t, mB, img.Digest)
	require.Equal(t, "linux/arm64", img.Platform)

	// Recorded platform digest: no registry call.
	before := fr.platformCalls
	cached := NewNormalizer(fr, mapLookup{platforms: map[string]string{idx + "|linux/arm64": mB}}, now)
	img, err = cached.Normalize(ctx, ContainerImage{Image: repo + ":1.27", ImageID: id, Node: arm64})
	require.NoError(t, err)
	require.Equal(t, mB, img.Digest)
	require.Equal(t, before, fr.platformCalls)

	// Already a platform digest.
	fr.platforms[mA+"|linux/amd64"] = registry.Manifest{Digest: mA}
	img, err = n.Normalize(ctx, ContainerImage{Image: repo + ":1.27", ImageID: repo + "@" + mA, Node: amd64})
	require.NoError(t, err)
	require.Equal(t, mA, img.Digest)
	require.Equal(t, "", img.IndexDigest)

	for _, c := range []struct {
		err    error
		reason string
	}{
		{registry.ErrUnauthorized, fmt.Sprintf(registry.ReasonUnauthorized, repo)},
		{registry.ErrNoPlatform, fmt.Sprintf(ReasonNoPlatform, idx, "linux/arm64")},
	} {
		fr.err = c.err
		img, err = n.Normalize(ctx, ContainerImage{Image: repo + ":1.27", ImageID: id, Node: arm64})
		require.NoError(t, err)
		require.Equal(t, model.ImageUnresolvable, img.Status)
		require.Equal(t, c.reason, img.StatusReason)
	}

	fr.err = registry.ErrRateLimited
	_, err = n.Normalize(ctx, ContainerImage{Image: repo + ":1.27", ImageID: id, Node: arm64})
	require.True(t, errors.Is(err, registry.ErrRateLimited))
}

func TestNormalize_StoredUnresolvableHonoursRetryWindow(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	stored := model.Image{Digest: idx, Status: model.ImageUnresolvable, Repo: "x", QuarantinedUntil: now.Add(time.Hour)}
	fr := &fakeResolver{platforms: map[string]registry.Manifest{idx + "|linux/amd64": {Digest: mA, IndexDigest: idx}}}
	n := NewNormalizer(fr, mapLookup{images: map[string]model.Image{idx: stored}}, func() time.Time { return now })
	in := ContainerImage{Image: "nginx:1", ImageID: "docker.io/library/nginx@" + idx, Node: NodePlatform{OS: "linux", Arch: "amd64"}}

	img, err := n.Normalize(ctx, in)
	require.NoError(t, err)
	require.Equal(t, model.ImageUnresolvable, img.Status)
	require.Equal(t, "docker.io/library/nginx", img.Repo)
	require.Zero(t, fr.platformCalls)

	n = NewNormalizer(fr, mapLookup{images: map[string]model.Image{idx: stored}}, func() time.Time { return now.Add(2 * time.Hour) })
	img, err = n.Normalize(ctx, in)
	require.NoError(t, err)
	require.Equal(t, mA, img.Digest)
}

func TestNormalize_CRIORepoFromStatusImage(t *testing.T) {
	fr := &fakeResolver{platforms: map[string]registry.Manifest{
		mA + "|linux/amd64": {Digest: mA},
	}}
	n := NewNormalizer(fr, emptyLookup{}, time.Now)
	amd64 := NodePlatform{OS: "linux", Arch: "amd64"}

	img, err := n.Normalize(ctx, ContainerImage{Image: "registry.example.com/app:1.0", ImageID: "quay.io/synth/name@" + mA, Node: amd64})
	require.NoError(t, err)
	require.Equal(t, "registry.example.com/app", img.Repo)
	require.Equal(t, mA, img.Digest)

	img, err = n.Normalize(ctx, ContainerImage{Image: cfg, ImageID: "docker.io/library/nginx@" + mA, Node: amd64})
	require.NoError(t, err)
	require.Equal(t, "docker.io/library/nginx", img.Repo)
}
