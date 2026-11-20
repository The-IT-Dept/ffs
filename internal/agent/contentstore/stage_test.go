package contentstore

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agent/contentstore/contentstoretest"
)

func TestStage_WritesOCILayout(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := Open(f.dir)
	target, err := s.Resolve(ctx, f.index, "linux/amd64")
	require.NoError(t, err)
	dst := filepath.Join(t.TempDir(), "work-1")
	require.NoError(t, s.Stage(ctx, target, dst, 1<<30))

	b, err := os.ReadFile(filepath.Join(dst, "oci-layout")) //nolint:gosec // G304: the test's own staged file
	require.NoError(t, err)
	require.Equal(t, `{"imageLayoutVersion":"1.0.0"}`, string(b))

	manifestBlob, err := os.Stat(filepath.Join(f.dir, "blobs", "sha256", strings.TrimPrefix(f.amd64.manifest, "sha256:")))
	require.NoError(t, err)
	b, err = os.ReadFile(filepath.Join(dst, "index.json")) //nolint:gosec // G304: the test's own staged file
	require.NoError(t, err)
	var idx struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"manifests"`
	}
	require.NoError(t, json.Unmarshal(b, &idx))
	require.Equal(t, 2, idx.SchemaVersion)
	require.Equal(t, string(types.OCIImageIndex), idx.MediaType)
	require.Len(t, idx.Manifests, 1)
	require.Equal(t, string(types.OCIManifestSchema1), idx.Manifests[0].MediaType)
	require.Equal(t, f.amd64.manifest, idx.Manifests[0].Digest)
	require.Equal(t, manifestBlob.Size(), idx.Manifests[0].Size)

	var blobs []string
	for _, d := range append([]string{f.amd64.manifest, f.amd64.config}, f.amd64.layers...) {
		blobs = append(blobs, strings.TrimPrefix(d, "sha256:"))
	}
	entries, err := os.ReadDir(filepath.Join(dst, "blobs", "sha256"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.ElementsMatch(t, blobs, names)

	require.NoError(t, filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		fi, err := os.Lstat(p)
		require.NoError(t, err)
		if d.IsDir() {
			require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm(), p)
		} else {
			require.Equal(t, fs.FileMode(0o644), fi.Mode().Perm(), p)
		}
		return nil
	}))

	ii, err := layout.ImageIndexFromPath(dst)
	require.NoError(t, err)
	im, err := ii.IndexManifest()
	require.NoError(t, err)
	require.Len(t, im.Manifests, 1)
	img, err := ii.Image(im.Manifests[0].Digest)
	require.NoError(t, err)
	d, err := img.Digest()
	require.NoError(t, err)
	require.Equal(t, f.amd64.manifest, d.String())
	layers, err := img.Layers()
	require.NoError(t, err)
	require.Len(t, layers, len(target.Layers))
}

func TestStage_LayersDiscarded(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := Open(f.dir)
	target, err := s.Resolve(ctx, f.amd64.manifest, "")
	require.NoError(t, err)
	contentstoretest.RemoveBlob(t, f.dir, f.amd64.layers[1])
	dst := filepath.Join(t.TempDir(), "work-1")
	err = s.Stage(ctx, target, dst, 1<<30)
	require.ErrorIs(t, err, ErrLayersDiscarded)
	_, err = os.Stat(dst)
	require.ErrorIs(t, err, fs.ErrNotExist)

	contentstoretest.RemoveBlob(t, f.dir, f.amd64.config)
	require.ErrorIs(t, s.Stage(ctx, target, dst, 1<<30), ErrNotFound, "a missing config is not a discarded layer")
}

func TestStage_TooLarge(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := Open(f.dir)
	target, err := s.Resolve(ctx, f.amd64.manifest, "")
	require.NoError(t, err)
	dst := filepath.Join(t.TempDir(), "work-1")
	require.ErrorIs(t, s.Stage(ctx, target, dst, target.Size-1), ErrTooLarge)
	_, err = os.Stat(dst)
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestStage_VerifiesDigests(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := Open(f.dir)
	target, err := s.Resolve(ctx, f.amd64.manifest, "")
	require.NoError(t, err)
	layer := filepath.Join(f.dir, "blobs", "sha256", strings.TrimPrefix(f.amd64.layers[0], "sha256:"))
	require.NoError(t, os.WriteFile(layer, []byte("other bytes"), 0o600))
	dst := filepath.Join(t.TempDir(), "work-1")
	err = s.Stage(ctx, target, dst, 1<<30)
	require.ErrorContains(t, err, "blob "+f.amd64.layers[0]+" does not match its digest")
	_, err = os.Stat(dst)
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestStage_StopsWhenCancelled(t *testing.T) {
	f := newFixture(t)
	s := Open(f.dir)
	target, err := s.Resolve(context.Background(), f.amd64.manifest, "")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := filepath.Join(t.TempDir(), "work-1")
	require.ErrorIs(t, s.Stage(ctx, target, dst, 1<<30), context.Canceled)
	_, err = os.Stat(dst)
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestStage_ScratchErrorsAreNotTheImages(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	s := Open(f.dir)
	target, err := s.Resolve(ctx, f.amd64.manifest, "")
	require.NoError(t, err)

	t.Run("blob path taken", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "work-1")
		require.NoError(t, os.MkdirAll(filepath.Join(dst, "blobs", "sha256", strings.TrimPrefix(target.Manifest, "sha256:")), 0o750))
		require.ErrorIs(t, s.Stage(ctx, target, dst, 1<<30), ErrScratch)
		_, err := os.Stat(dst)
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
	t.Run("write fails", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "blob")
		require.NoError(t, err)
		require.NoError(t, file.Close())
		_, err = io.Copy(scratchWriter{file}, strings.NewReader("layer bytes"))
		require.ErrorIs(t, err, ErrScratch)
	})
	t.Run("not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes to read-only dirs")
		}
		parent := t.TempDir()
		require.NoError(t, os.Chmod(parent, 0o500))       //nolint:gosec // G302: a scratch dir the collector cannot write
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) }) //nolint:gosec // G302: let the test clean up
		err := s.Stage(ctx, target, filepath.Join(parent, "work-1"), 1<<30)
		require.ErrorIs(t, err, ErrScratch)
		require.ErrorIs(t, err, fs.ErrPermission)
	})
	t.Run("content store unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads unreadable files")
		}
		layer := filepath.Join(f.dir, "blobs", "sha256", strings.TrimPrefix(f.amd64.layers[0], "sha256:"))
		require.NoError(t, os.Chmod(layer, 0o000))
		t.Cleanup(func() { _ = os.Chmod(layer, 0o600) })
		err := s.Stage(ctx, target, filepath.Join(t.TempDir(), "work-1"), 1<<30)
		require.ErrorIs(t, err, fs.ErrPermission)
		require.NotErrorIs(t, err, ErrScratch, "reading the content store is not a scratch failure")
	})
}
