//go:build e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

// The app image's packages: a Debian 12 dpkg package built from source package "example" at
// 1.0-1, and a file that Syft's php-interpreter-cataloger reads as php-cli 8.3.10.
const (
	osRelease = `ID=debian
VERSION_ID="12"
VERSION_CODENAME=bookworm
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
`
	dpkgStatus = `Package: libexample1
Status: install ok installed
Architecture: all
Source: example
Version: 1.0-1
Maintainer: ffs e2e <e2e@example.invalid>
Description: ffs e2e fixture

`
	phpBinary = "PHP 8.3.10 (cli)\x00X-Powered-By: PHP/8.3.10\x00"
)

// buildSleeper cross-compiles testdata/sleeper for linux/goarch and returns the binary.
func buildSleeper(t *testing.T, goarch string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "sleeper")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", out, "./testdata/sleeper") //nolint:gosec // G204: fixed command; out is a temp path
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	b, err := cmd.CombinedOutput()
	require.NoError(t, err, "build sleeper for %s: %s", goarch, b)
	bin, err := os.ReadFile(out) //nolint:gosec // G304: a temp path this test wrote
	require.NoError(t, err)
	return bin
}

// appImage returns the linux/goarch app image: one gzip layer with the sleeper as entrypoint, the
// Debian os-release and dpkg status, and the php fixture, run as user 65532.
func appImage(t *testing.T, goarch string) v1.Image {
	t.Helper()
	files := []struct {
		name string
		mode int64
		body []byte
	}{
		{"sleeper", 0o755, buildSleeper(t, goarch)},
		{"etc/os-release", 0o644, []byte(osRelease)},
		{"var/lib/dpkg/status", 0o644, []byte(dpkgStatus)},
		{"usr/local/bin/php", 0o755, []byte(phpBinary)},
	}
	epoch := time.Unix(0, 0)
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, dir := range []string{"etc/", "usr/", "usr/local/", "usr/local/bin/", "var/", "var/lib/", "var/lib/dpkg/"} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: dir, Mode: 0o755, ModTime: epoch}))
	}
	for _, f := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: f.name, Mode: f.mode, Size: int64(len(f.body)), ModTime: epoch}))
		_, err := tw.Write(f.body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw.Bytes())), nil
	}, tarball.WithMediaType(types.OCILayer))
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)
	img = mutate.ConfigMediaType(mutate.MediaType(img, types.OCIManifestSchema1), types.OCIConfigJSON)
	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture = "linux", goarch
	cfg.Config.Entrypoint = []string{"/sleeper"}
	cfg.Config.User = "65532"
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)
	return img
}

// pushAppIndex pushes an OCI index of the linux/amd64 and linux/arm64 app images to ref and
// returns the index digest.
func pushAppIndex(t *testing.T, ref string) string {
	t.Helper()
	var adds []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "arm64"} {
		adds = append(adds, mutate.IndexAddendum{
			Add:        appImage(t, arch),
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	idx := mutate.AppendManifests(mutate.IndexMediaType(empty.Index, types.OCIImageIndex), adds...)
	r, err := name.ParseReference(ref, name.Insecure) // the fixture registry speaks plain HTTP
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(r, idx, remote.WithContext(t.Context())))
	d, err := idx.Digest()
	require.NoError(t, err)
	return d.String()
}
