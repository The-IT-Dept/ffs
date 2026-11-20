package contentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agent/contentstore/contentstoretest"
	"github.com/the-it-dept/ffs/internal/agentapi/wire"
)

// platformImage is a random two-layer image for os/arch[/variant], with OCI or Docker media types.
func platformImage(t *testing.T, os, arch, variant string, mt types.MediaType) v1.Image {
	t.Helper()
	img, err := random.Image(512, 2)
	require.NoError(t, err)
	cf, err := img.ConfigFile()
	require.NoError(t, err)
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = os, arch, variant
	img, err = mutate.ConfigFile(img, cf)
	require.NoError(t, err)
	if mt == types.OCIManifestSchema1 {
		img = mutate.ConfigMediaType(mutate.MediaType(img, types.OCIManifestSchema1), types.OCIConfigJSON)
	}
	return img
}

type image struct {
	img              v1.Image
	manifest, config string
	layers           []string
	size             int64
}

func describe(t *testing.T, img v1.Image) image {
	t.Helper()
	m, err := img.Manifest()
	require.NoError(t, err)
	d, err := img.Digest()
	require.NoError(t, err)
	out := image{img: img, manifest: d.String(), config: m.Config.Digest.String(), size: m.Config.Size}
	for _, l := range m.Layers {
		out.layers = append(out.layers, l.Digest.String())
		out.size += l.Size
	}
	return out
}

type fixture struct {
	dir                          string
	index                        string
	amd64, arm64, docker, attest image
}

// newFixture writes an OCI index of linux/amd64 and linux/arm64/v8, a lone Docker schema 2 image and an
// attestation manifest into a fresh content store.
func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{dir: filepath.Join(t.TempDir(), "io.containerd.content.v1.content")}
	amd := platformImage(t, "linux", "amd64", "", types.OCIManifestSchema1)
	arm := platformImage(t, "linux", "arm64", "v8", types.OCIManifestSchema1)
	idx := mutate.IndexMediaType(mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: arm, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}},
	), types.OCIImageIndex)
	f.index = contentstoretest.WriteIndex(t, f.dir, idx)
	f.amd64, f.arm64 = describe(t, amd), describe(t, arm)

	docker := platformImage(t, "linux", "amd64", "", types.DockerManifestSchema2)
	contentstoretest.WriteImage(t, f.dir, docker)
	f.docker = describe(t, docker)

	attest := mutate.ConfigMediaType(platformImage(t, "unknown", "unknown", "", types.OCIManifestSchema1), "application/vnd.in-toto+json")
	contentstoretest.WriteImage(t, f.dir, attest)
	f.attest = describe(t, attest)
	return f
}

// writeBlob writes content as a blob named by its sha256 and returns the digest.
func writeBlob(t *testing.T, dir string, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	h := hex.EncodeToString(sum[:])
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blobs", "sha256", h), content, 0o600))
	return "sha256:" + h
}

func TestScan_ClassifiesManifestsAndIndexes(t *testing.T) {
	f := newFixture(t)
	got, err := Open(f.dir).Scan(context.Background())
	require.NoError(t, err)

	want := []wire.CachedImage{
		{Digest: f.index, MediaType: string(types.OCIImageIndex), Manifests: []string{f.amd64.manifest, f.arm64.manifest},
			Size: f.amd64.size + f.arm64.size, Complete: true},
		{Digest: f.amd64.manifest, MediaType: string(types.OCIManifestSchema1), ConfigDigest: f.amd64.config, Platform: "linux/amd64",
			Size: f.amd64.size, Complete: true},
		{Digest: f.arm64.manifest, MediaType: string(types.OCIManifestSchema1), ConfigDigest: f.arm64.config, Platform: "linux/arm64/v8",
			Size: f.arm64.size, Complete: true},
		{Digest: f.docker.manifest, MediaType: "application/vnd.docker.distribution.manifest.v2+json", ConfigDigest: f.docker.config,
			Platform: "linux/amd64", Size: f.docker.size, Complete: true},
	}
	sortImages(want)
	require.Equal(t, want, got)
	for _, img := range got {
		require.NotEqual(t, f.attest.manifest, img.Digest, "an attestation manifest is not an image")
	}
}

func sortImages(imgs []wire.CachedImage) {
	for i := 1; i < len(imgs); i++ {
		for j := i; j > 0 && imgs[j].Digest < imgs[j-1].Digest; j-- {
			imgs[j], imgs[j-1] = imgs[j-1], imgs[j]
		}
	}
}

func TestScan_ReadsOnlySmallJSONBlobsAndCaches(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "content")
	big := append([]byte{'{'}, bytes.Repeat([]byte{' '}, 5<<20)...)
	big = append(big, '}')
	writeBlob(t, dir, big)
	writeBlob(t, dir, append([]byte{'x'}, bytes.Repeat([]byte{'{'}, 1023)...))
	img := platformImage(t, "linux", "amd64", "", types.OCIManifestSchema1)
	contentstoretest.WriteImage(t, dir, img)

	s := Open(dir)
	got, err := s.Scan(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, 2, s.fullReads, "only the manifest and config blobs are read in full")

	_, err = s.Scan(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, s.fullReads, "classifications are cached per blob")

	contentstoretest.WriteImage(t, dir, platformImage(t, "linux", "arm64", "", types.OCIManifestSchema1))
	got, err = s.Scan(ctx)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, 4, s.fullReads, "only the new image's JSON blobs are read")
}

func TestScan_IncompleteWhenLayerMissing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := Open(f.dir)
	byDigest := func() map[string]wire.CachedImage {
		got, err := s.Scan(ctx)
		require.NoError(t, err)
		m := map[string]wire.CachedImage{}
		for _, img := range got {
			m[img.Digest] = img
		}
		return m
	}
	require.True(t, byDigest()[f.amd64.manifest].Complete)

	contentstoretest.RemoveBlob(t, f.dir, f.amd64.layers[0])
	got := byDigest()
	require.False(t, got[f.amd64.manifest].Complete, "completeness is re-checked on every Scan")
	require.True(t, got[f.index].Complete, "the arm64 child is still complete")
	require.Equal(t, f.amd64.size+f.arm64.size, got[f.index].Size)

	contentstoretest.RemoveBlob(t, f.dir, f.arm64.layers[1])
	got = byDigest()
	require.False(t, got[f.arm64.manifest].Complete)
	require.False(t, got[f.index].Complete, "no child is complete")

	entries, err := os.ReadDir(filepath.Join(f.dir, "blobs", "sha256"))
	require.NoError(t, err)
	for _, e := range entries {
		contentstoretest.RemoveBlob(t, f.dir, "sha256:"+e.Name())
	}
	all, err := s.Scan(ctx)
	require.NoError(t, err)
	require.Empty(t, all)
	require.Empty(t, s.blobs, "the cache is pruned to the listed blobs")
}

func TestScan_MissingStore(t *testing.T) {
	_, err := Open(t.TempDir() + "/nope").Scan(context.Background())
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestScan_UnreadableStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads directories whatever their mode")
	}
	f := newFixture(t)
	blobs := filepath.Join(f.dir, "blobs", "sha256")
	require.NoError(t, os.Chmod(blobs, 0))
	t.Cleanup(func() { _ = os.Chmod(blobs, 0o700) }) //nolint:gosec // G302: restores the test dir for cleanup
	_, err := Open(f.dir).Scan(context.Background())
	require.ErrorIs(t, err, fs.ErrPermission)
}

func TestResolve_ManifestIndexAndConfig(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := Open(f.dir)

	target := func(img image, mt string) Target {
		return Target{MediaType: mt, Manifest: img.manifest, Config: img.config, Layers: img.layers, Size: img.size}
	}
	got, err := s.Resolve(ctx, f.index, "linux/arm64")
	require.NoError(t, err)
	require.Equal(t, target(f.arm64, string(types.OCIManifestSchema1)), got)

	got, err = s.Resolve(ctx, f.index, "linux/arm64/v8")
	require.NoError(t, err)
	require.Equal(t, f.arm64.manifest, got.Manifest)
	_, err = s.Resolve(ctx, f.index, "linux/arm64/v7")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.Resolve(ctx, f.index, "linux/s390x")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.Resolve(ctx, f.index, "")
	require.ErrorIs(t, err, ErrNotFound)

	got, err = s.Resolve(ctx, f.amd64.manifest, "")
	require.NoError(t, err)
	require.Equal(t, target(f.amd64, string(types.OCIManifestSchema1)), got)

	got, err = s.Resolve(ctx, f.amd64.config, "")
	require.NoError(t, err)
	require.Equal(t, f.amd64.manifest, got.Manifest, "a bare config digest, as kubelet reports side-loaded images")

	got, err = s.Resolve(ctx, f.docker.manifest, "linux/amd64")
	require.NoError(t, err)
	require.Equal(t, target(f.docker, "application/vnd.docker.distribution.manifest.v2+json"), got)

	_, err = s.Resolve(ctx, "sha256:"+string(bytes.Repeat([]byte{'0'}, 64)), "linux/amd64")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = s.Resolve(ctx, f.attest.manifest, "")
	require.ErrorIs(t, err, ErrNotFound, "an attestation is not an image")
	_, err = s.Resolve(ctx, f.amd64.layers[0], "")
	require.ErrorIs(t, err, ErrNotFound, "a layer is not an image")

	// An image written after the last listing is found without an explicit Scan.
	late := platformImage(t, "linux", "riscv64", "", types.OCIManifestSchema1)
	m, c := contentstoretest.WriteImage(t, f.dir, late)
	got, err = s.Resolve(ctx, c, "")
	require.NoError(t, err)
	require.Equal(t, m, got.Manifest)
}

func TestResolve_ConfigPrefersCompleteManifest(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "content")
	cfg := writeBlob(t, dir, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}`))
	layer := writeBlob(t, dir, []byte("layer bytes"))
	manifest := func(layerDigest, note string) []byte {
		return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
			`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"` + cfg + `","size":10},` +
			`"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"` + layerDigest + `","size":11}],` +
			`"annotations":{"note":"` + note + `"}}`)
	}
	complete := writeBlob(t, dir, manifest(layer, "complete"))
	// An incomplete manifest naming the same config, with a lower digest than the complete one.
	missing := "sha256:" + string(bytes.Repeat([]byte{'b'}, 64))
	var incomplete string
	for i := 0; ; i++ {
		b := manifest(missing, "incomplete-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		sum := sha256.Sum256(b)
		if d := "sha256:" + hex.EncodeToString(sum[:]); d < complete {
			incomplete = writeBlob(t, dir, b)
			break
		}
	}
	require.Less(t, incomplete, complete)

	got, err := Open(dir).Resolve(ctx, cfg, "")
	require.NoError(t, err)
	require.Equal(t, complete, got.Manifest, "complete manifests first, then the lowest digest")
}

func TestResolve_MissingStoreIsNotFound(t *testing.T) {
	_, err := Open(t.TempDir()+"/nope").Resolve(context.Background(), "sha256:"+string(bytes.Repeat([]byte{'a'}, 64)), "")
	require.ErrorIs(t, err, ErrNotFound)
}

// attestationImage is an attestation manifest as BuildKit writes it: an OCI image manifest with an OCI image
// config for os/arch (unknown/unknown from BuildKit) and one in-toto statement layer.
func attestationImage(t *testing.T, os, arch string) v1.Image {
	t.Helper()
	stmt := static.NewLayer([]byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document"}`),
		"application/vnd.in-toto+json")
	img, err := mutate.Append(empty.Image, mutate.Addendum{Layer: stmt,
		Annotations: map[string]string{"in-toto.io/predicate-type": "https://spdx.dev/Document"}})
	require.NoError(t, err)
	cf, err := img.ConfigFile()
	require.NoError(t, err)
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = os, arch
	img, err = mutate.ConfigFile(img, cf)
	require.NoError(t, err)
	return mutate.ConfigMediaType(mutate.MediaType(img, types.OCIManifestSchema1), types.OCIConfigJSON)
}

func TestScan_SkipsBuildKitAttestations(t *testing.T) {
	ctx := context.Background()
	annotations := func(subject string) map[string]string {
		return map[string]string{"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": subject}
	}
	unknown := &v1.Platform{OS: "unknown", Architecture: "unknown"}
	for name, tc := range map[string]struct {
		configOS, configArch string
		platform             *v1.Platform
		annotated            bool
	}{
		"as BuildKit writes it": {"unknown", "unknown", unknown, true},
		"by annotation":         {"linux", "amd64", nil, true},
		"by index platform":     {"linux", "amd64", unknown, false},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "io.containerd.content.v1.content")
			amd := describe(t, platformImage(t, "linux", "amd64", "", types.OCIManifestSchema1))
			att := describe(t, attestationImage(t, tc.configOS, tc.configArch))
			desc := v1.Descriptor{Platform: tc.platform}
			if tc.annotated {
				desc.Annotations = annotations(amd.manifest)
			}
			index := contentstoretest.WriteIndex(t, dir, mutate.IndexMediaType(mutate.AppendManifests(empty.Index,
				mutate.IndexAddendum{Add: amd.img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
				mutate.IndexAddendum{Add: att.img, Descriptor: desc},
			), types.OCIImageIndex))

			s := Open(dir)
			got, err := s.Scan(ctx)
			require.NoError(t, err)
			want := []wire.CachedImage{
				{Digest: index, MediaType: string(types.OCIImageIndex), Manifests: []string{amd.manifest, att.manifest}, Size: amd.size, Complete: true},
				{Digest: amd.manifest, MediaType: string(types.OCIManifestSchema1), ConfigDigest: amd.config, Platform: "linux/amd64",
					Size: amd.size, Complete: true},
			}
			sortImages(want)
			require.Equal(t, want, got, "the attestation is not a cached image")

			for _, d := range []string{att.manifest, att.config} {
				_, err = s.Resolve(ctx, d, "")
				require.ErrorIs(t, err, ErrNotFound, d)
			}
			_, err = s.Resolve(ctx, index, "unknown/unknown")
			require.ErrorIs(t, err, ErrNotFound)
			tg, err := s.Resolve(ctx, index, "linux/amd64")
			require.NoError(t, err)
			require.Equal(t, amd.manifest, tg.Manifest)
		})
	}
}
