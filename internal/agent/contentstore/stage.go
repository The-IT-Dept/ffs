package contentstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ociLayout is the oci-layout file of every staged layout.
const ociLayout = `{"imageLayoutVersion":"1.0.0"}`

type layoutDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type layoutIndex struct {
	SchemaVersion int                `json:"schemaVersion"`
	MediaType     string             `json:"mediaType"`
	Manifests     []layoutDescriptor `json:"manifests"`
}

// Stage writes t as an OCI image layout at dst: oci-layout, an index.json naming the manifest, and
// blobs/sha256/<hex> for the manifest, the config and every layer (files 0644, dirs 0755). It returns an error
// wrapping ErrTooLarge when the image is over maxBytes (nothing is written), ErrNotFound when the manifest or
// config blob is missing, ErrLayersDiscarded when a layer blob is missing, and ErrScratch when dst cannot be
// written. Every blob is checked against its digest as it is copied. On any error dst is removed.
func (s *Store) Stage(ctx context.Context, t Target, dst string, maxBytes int64) (err error) {
	if t.Size > maxBytes {
		return fmt.Errorf("%w: %s is %d bytes, the limit is %d", ErrTooLarge, t.Manifest, t.Size, maxBytes)
	}
	manifestSize, err := s.present(t.Manifest, ErrNotFound, "manifest")
	if err != nil {
		return err
	}
	if _, err := s.present(t.Config, ErrNotFound, "config"); err != nil {
		return err
	}
	for _, l := range t.Layers {
		if _, err := s.present(l, ErrLayersDiscarded, "layer"); err != nil {
			return err
		}
	}

	defer func() {
		if err != nil {
			_ = os.RemoveAll(dst)
		}
	}()
	blobs := filepath.Join(dst, "blobs", "sha256")
	for _, d := range []string{dst, filepath.Join(dst, "blobs"), blobs} {
		if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // G301: the non-root cataloguer reads the staged layout
			return scratchErr(err)
		}
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // G302: the non-root cataloguer reads the staged layout
			return scratchErr(err)
		}
	}

	if _, err := s.copyBlob(ctx, t.Manifest, blobs, MaxManifestBytes); err != nil {
		return err
	}
	budget := maxBytes
	done := map[string]bool{t.Manifest: true}
	for _, d := range append([]string{t.Config}, t.Layers...) {
		if done[d] {
			continue
		}
		done[d] = true
		n, err := s.copyBlob(ctx, d, blobs, budget)
		if err != nil {
			return err
		}
		budget -= n
	}

	idx, err := json.Marshal(layoutIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests:     []layoutDescriptor{{MediaType: t.MediaType, Digest: t.Manifest, Size: manifestSize}},
	})
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dst, "oci-layout"), []byte(ociLayout)); err != nil {
		return err
	}
	return writeFile(filepath.Join(dst, "index.json"), idx)
}

// present stats a blob, returning its size, or an error wrapping missing when it is not in the store.
func (s *Store) present(digest string, missing error, what string) (int64, error) {
	if !strings.HasPrefix(digest, "sha256:") || !isHex64(strings.TrimPrefix(digest, "sha256:")) {
		return 0, fmt.Errorf("%w: %s digest %q is not a sha256 digest", ErrNotFound, what, digest)
	}
	fi, err := os.Stat(s.blobPath(digest))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, fmt.Errorf("%w: %s %s is not in the content store", missing, what, digest)
	}
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// copyBlob copies one blob into blobs (0644), checking its sha256, and returns its size. A blob larger than
// limit gives an error wrapping ErrTooLarge.
func (s *Store) copyBlob(ctx context.Context, digest, blobs string, limit int64) (int64, error) {
	in, err := os.Open(s.blobPath(digest))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, fmt.Errorf("%w: %s was removed from the content store", ErrLayersDiscarded, digest)
		}
		return 0, err
	}
	defer in.Close() //nolint:errcheck // read-only
	hex64 := strings.TrimPrefix(digest, "sha256:")
	out, err := os.OpenFile(filepath.Join(blobs, hex64), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // G302/G304: the non-root cataloguer reads the staged layout
	if err != nil {
		return 0, scratchErr(err)
	}
	h := sha256.New()
	// Write errors come back wrapping ErrScratch; read errors, from the content store, as they are.
	n, err := io.Copy(scratchWriter{out}, io.TeeReader(&ctxReader{ctx: ctx, r: io.LimitReader(in, limit+1)}, h))
	if err == nil {
		err = scratchErr(out.Chmod(0o644)) //nolint:gosec // G302: the non-root cataloguer reads the staged layout
	}
	if cerr := out.Close(); err == nil {
		err = scratchErr(cerr)
	}
	switch {
	case err != nil:
		return 0, err
	case n > limit:
		return 0, fmt.Errorf("%w: blob %s is larger than %d bytes", ErrTooLarge, digest, limit)
	case hex.EncodeToString(h.Sum(nil)) != hex64:
		return 0, fmt.Errorf("blob %s does not match its digest", digest)
	}
	return n, nil
}

// writeFile writes a small file of the staged layout; its error wraps ErrScratch.
func writeFile(p string, b []byte) error {
	if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // G306: the non-root cataloguer reads the staged layout
		return scratchErr(err)
	}
	return scratchErr(os.Chmod(p, 0o644)) //nolint:gosec // G302: the non-root cataloguer reads the staged layout
}

// scratchErr wraps a failure to write the staged layout in ErrScratch; nil stays nil.
func scratchErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrScratch, err)
}

// scratchWriter tells write errors (the staged layout) from read errors (the content store) in io.Copy.
type scratchWriter struct{ w io.Writer }

func (s scratchWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	return n, scratchErr(err)
}

// ctxReader stops a copy once its context is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
