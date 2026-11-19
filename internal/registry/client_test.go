package registry

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/registry/regtest"
)

var (
	ctx         = context.Background()
	manifestsRe = regexp.MustCompile(`/manifests/`)
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func randomImage(t *testing.T) v1.Image {
	t.Helper()
	img, err := random.Image(128, 1)
	require.NoError(t, err)
	return img
}

func digestOf(t *testing.T, img v1.Image) string {
	t.Helper()
	d, err := img.Digest()
	require.NoError(t, err)
	return d.String()
}

// within returns a context that fails any call waiting longer than d.
func within(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(ctx, d)
	t.Cleanup(cancel)
	return c
}

func TestPlatformManifest_IndexPerArch(t *testing.T) {
	s := regtest.Start(t)
	idx, imgs := regtest.PlatformIndex(t, map[string]string{AnnotationVersion: "1.27.3"}, "linux/amd64", "linux/arm64/v8", "linux/arm/v6", "linux/arm/v7")
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: randomImage(t), Descriptor: v1.Descriptor{
		Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
		Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
	}})
	idxDigest := s.PushIndex(t, "nginx:1.27.3", idx)
	repo := s.Host + "/nginx"
	c := New(Options{})

	// A single-arch manifest digest costs a HEAD only.
	amd := digestOf(t, imgs["linux/amd64"])
	m, err := c.PlatformManifest(ctx, repo, amd, "linux/amd64", CredSet{})
	require.NoError(t, err)
	require.Equal(t, Manifest{Digest: amd, Platform: "linux/amd64"}, m)
	require.Equal(t, 0, s.Count("GET", manifestsRe))

	m, err = c.PlatformManifest(ctx, repo, idxDigest, "linux/arm64", CredSet{})
	require.NoError(t, err)
	require.Equal(t, digestOf(t, imgs["linux/arm64/v8"]), m.Digest)
	require.Equal(t, idxDigest, m.IndexDigest)
	require.Equal(t, "linux/arm64", m.Platform)
	require.Equal(t, "1.27.3", m.Annotations[AnnotationVersion])

	for platform, want := range map[string]string{"linux/arm": "linux/arm/v7", "linux/arm/v6": "linux/arm/v6", "linux/amd64": "linux/amd64"} {
		m, err = c.PlatformManifest(ctx, repo, idxDigest, platform, CredSet{})
		require.NoError(t, err, platform)
		require.Equal(t, digestOf(t, imgs[want]), m.Digest, platform)
	}

	_, err = c.PlatformManifest(ctx, repo, idxDigest, "linux/s390x", CredSet{})
	require.ErrorIs(t, err, ErrNoPlatform)

	cfg, err := c.ConfigDigest(ctx, repo, amd, CredSet{})
	require.NoError(t, err)
	name, err := imgs["linux/amd64"].ConfigName()
	require.NoError(t, err)
	require.Equal(t, name.String(), cfg)
}

func TestResolveTag_UsesHEAD(t *testing.T) {
	s := regtest.Start(t)
	img := randomImage(t)
	s.Push(t, "app:1.0", img)
	c := New(Options{})

	d, err := c.ResolveTag(ctx, s.Host+"/app", "1.0", CredSet{})
	require.NoError(t, err)
	require.Equal(t, digestOf(t, img), d)
	require.Equal(t, 0, s.Count("GET", manifestsRe))
	require.Equal(t, 1, s.Count("HEAD", regexp.MustCompile(`^/v2/app/manifests/1\.0$`)))

	_, err = c.ResolveTag(ctx, s.Host+"/app", "2.0", CredSet{})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestReferrers(t *testing.T) {
	plain := regtest.Start(t)
	d := plain.Push(t, "app:1", randomImage(t))
	c := New(Options{})
	descs, err := c.Referrers(ctx, plain.Host+"/app", d, CredSet{})
	require.NoError(t, err)
	require.Nil(t, descs)

	s := regtest.Start(t, regtest.WithReferrers())
	img := randomImage(t)
	d = s.Push(t, "app:1", img)
	mt, err := img.MediaType()
	require.NoError(t, err)
	size, err := img.Size()
	require.NoError(t, err)
	h, err := v1.NewHash(d)
	require.NoError(t, err)
	art := mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), "application/vnd.example.sbom+json")
	art = mutate.Subject(art, v1.Descriptor{MediaType: mt, Size: size, Digest: h}).(v1.Image)
	s.Push(t, "app", art)

	descs, err = c.Referrers(ctx, s.Host+"/app", d, CredSet{})
	require.NoError(t, err)
	require.Len(t, descs, 1)
	require.Equal(t, "application/vnd.example.sbom+json", descs[0].ArtifactType)
	require.Equal(t, digestOf(t, art), descs[0].Digest.String())
	require.Equal(t, 1, s.Count("GET", regexp.MustCompile(`/referrers/`)))
	require.Equal(t, 0, s.Count("GET", regexp.MustCompile(`/manifests/sha256-`)))
}

func TestMirror_PullLocationOnly(t *testing.T) {
	s := regtest.Start(t)
	img := randomImage(t)
	s.Push(t, "hub/library/nginx:1.27", img)
	c := New(Options{Config: config.RegistryConfig{Mirrors: map[string]string{"docker.io": s.Host + "/hub"}}})

	require.Equal(t, s.Host+"/hub/library/nginx", c.PullRepo("docker.io/library/nginx"))
	require.Equal(t, "ghcr.io/x/y", c.PullRepo("ghcr.io/x/y"))
	d, err := c.ResolveTag(ctx, "docker.io/library/nginx", "1.27", CredSet{})
	require.NoError(t, err)
	require.Equal(t, digestOf(t, img), d)
	require.Equal(t, 1, s.Count("HEAD", regexp.MustCompile(`^/v2/hub/library/nginx/manifests/1\.27$`)))

	// index.docker.io is the same registry as docker.io.
	c = New(Options{Config: config.RegistryConfig{Mirrors: map[string]string{"index.docker.io": s.Host + "/hub/"}}})
	require.Equal(t, s.Host+"/hub/library/nginx", c.PullRepo("docker.io/library/nginx"))
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{&transport.Error{StatusCode: 401}, ErrUnauthorized},
		{&transport.Error{StatusCode: 403}, ErrUnauthorized},
		{&transport.Error{StatusCode: 404}, ErrNotFound},
		{&transport.Error{StatusCode: 400, Errors: []transport.Diagnostic{{Code: transport.ManifestUnknownErrorCode}}}, ErrNotFound},
		{&transport.Error{StatusCode: 400, Errors: []transport.Diagnostic{{Code: transport.NameUnknownErrorCode}}}, ErrNotFound},
		{&transport.Error{StatusCode: 429}, ErrRateLimited},
		{fmt.Errorf("HEAD: %w", &transport.Error{StatusCode: 401}), ErrUnauthorized},
	}
	for _, tc := range cases {
		got := Classify(tc.err)
		require.ErrorIs(t, got, tc.want, tc.err.Error())
		var te *transport.Error
		require.ErrorAs(t, got, &te)
	}

	for _, err := range []error{&transport.Error{StatusCode: 500}, errors.New("dial tcp: refused"), context.DeadlineExceeded} {
		require.Equal(t, err, Classify(err))
	}
	require.NoError(t, Classify(nil))
	once := Classify(&transport.Error{StatusCode: 404})
	require.Equal(t, once, Classify(once))
}
