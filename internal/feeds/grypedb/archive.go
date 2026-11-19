package grypedb

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/klauspost/compress/zstd"

	"github.com/the-it-dept/ffs/internal/feeds"
)

// maxExtracted caps the total size of the files extracted from one archive.
const maxExtracted int64 = 8 << 30

// extract unpacks the tar.zst at archive into the existing, empty directory dst. Only regular
// files named exactly vulnerability.db or import.json are accepted; any other entry fails with
// ErrUnsafeArchive before anything is written for it. vulnerability.db must be present.
func extract(archive, dst string) error {
	f, err := os.Open(archive) //nolint:gosec // G304: archive is our own download path under the data directory
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	zr, err := zstd.NewReader(f, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return fmt.Errorf("grypedb: open archive: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	var total int64
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("grypedb: read archive: %w", err)
		}
		name, ok := allowedName(hdr)
		if !ok {
			return fmt.Errorf("%w: entry %q (type %q)", ErrUnsafeArchive, hdr.Name, hdr.Typeflag)
		}
		if seen[name] {
			return fmt.Errorf("%w: duplicate entry %q", ErrUnsafeArchive, name)
		}
		seen[name] = true
		if hdr.Size < 0 || total+hdr.Size > maxExtracted {
			return fmt.Errorf("%w: archive expands past %d bytes", feeds.ErrTooLarge, maxExtracted)
		}
		n, err := writeFile(filepath.Join(dst, name), tr)
		total += n
		if err != nil {
			return err
		}
	}
	if !seen[v6.VulnerabilityDBFileName] {
		return fmt.Errorf("grypedb: archive has no %s", v6.VulnerabilityDBFileName)
	}
	return nil
}

// allowedName returns the fixed file name for an accepted entry: a regular file named exactly
// vulnerability.db or import.json. The returned name is the constant, never the header's string.
func allowedName(hdr *tar.Header) (string, bool) {
	if hdr.Typeflag != tar.TypeReg {
		return "", false
	}
	switch hdr.Name {
	case v6.VulnerabilityDBFileName:
		return v6.VulnerabilityDBFileName, true
	case v6.ImportMetadataFileName:
		return v6.ImportMetadataFileName, true
	}
	return "", false
}

func writeFile(path string, r io.Reader) (int64, error) {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is dst joined with one of two fixed names
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, r)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, fmt.Errorf("grypedb: extract %s: %w", filepath.Base(path), err)
	}
	return n, nil
}
