// Package contentstoretest builds containerd-style content stores for tests: blobs under blobs/sha256, written
// with go-containerregistry's layout writer.
package contentstoretest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// WriteImage writes the manifest, config and layer blobs of img into the content store dir and returns the
// manifest and config digests.
func WriteImage(t testing.TB, dir string, img v1.Image) (manifest, config string) {
	t.Helper()
	if err := layout.Path(dir).WriteImage(img); err != nil {
		t.Fatalf("writing image blobs: %v", err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatalf("image digest: %v", err)
	}
	c, err := img.ConfigName()
	if err != nil {
		t.Fatalf("image config digest: %v", err)
	}
	return d.String(), c.String()
}

// WriteIndex writes idx and every child image or index into the content store dir and returns the index digest.
func WriteIndex(t testing.TB, dir string, idx v1.ImageIndex) string {
	t.Helper()
	if err := layout.Path(dir).WriteIndex(idx); err != nil {
		t.Fatalf("writing index blobs: %v", err)
	}
	d, err := idx.Digest()
	if err != nil {
		t.Fatalf("index digest: %v", err)
	}
	return d.String()
}

// RemoveBlob deletes one blob from the content store dir, as containerd does when it discards unpacked layers.
func RemoveBlob(t testing.TB, dir, digest string) {
	t.Helper()
	p := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
	if err := os.Remove(p); err != nil {
		t.Fatalf("removing blob %s: %v", digest, err)
	}
}
