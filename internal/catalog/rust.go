package catalog

import (
	"bytes"
	"errors"
	"io"

	"github.com/anchore/syft/syft/file"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"

	"github.com/the-it-dept/ffs/internal/sbom"
)

const (
	// maxRustCandidates bounds the unattributed ELF executables scanned per image.
	maxRustCandidates = 500
	// maxRustScan bounds the bytes scanned per executable.
	maxRustScan   = 256 << 20
	rustScanChunk = 1 << 20
	rustcHexLen   = 40
)

// rustcPrefix starts the path rustc embeds for its standard library sources, "/rustc/<commit>/library/...".
var rustcPrefix = []byte("/rustc/")

// rustcMarkLen is the length of a full marker: the prefix and a 40-character commit hash.
var rustcMarkLen = len(rustcPrefix) + rustcHexLen

// markRust adds sbom.UnknownRustNoAuditable to each unattributed ELF executable (up to
// maxRustCandidates) that rustc built. Syft attributes a Rust binary to packages only when it
// carries cargo-auditable metadata, so an unattributed one has none.
func markRust(doc *syftsbom.SBOM, src source.Source) error {
	candidates := sbom.UnattributedELF(doc)
	if len(candidates) == 0 {
		return nil
	}
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		return err
	}
	if len(candidates) > maxRustCandidates {
		candidates = candidates[:maxRustCandidates]
	}
	for _, c := range candidates {
		ok, err := builtByRustc(resolver, c)
		if err != nil {
			continue // unreadable: left as a plain unattributed executable
		}
		if ok {
			doc.Artifacts.Unknowns[c] = append(doc.Artifacts.Unknowns[c], sbom.UnknownRustNoAuditable)
		}
	}
	return nil
}

// builtByRustc reports whether the file at c contains a rustc source path. The coordinates are
// resolved through the resolver, because an image resolver opens contents by file reference, which
// bare coordinates do not carry.
func builtByRustc(resolver file.Resolver, c file.Coordinates) (bool, error) {
	locs, err := resolver.FilesByPath(c.RealPath)
	if err != nil {
		return false, err
	}
	loc := file.NewLocationFromCoordinates(c)
	for _, l := range locs {
		if l.FileSystemID == c.FileSystemID {
			loc = l
			break
		}
	}
	rc, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return false, err
	}
	defer func() { _ = rc.Close() }()
	return hasRustcPath(rc, maxRustScan)
}

// hasRustcPath streams at most limit bytes of r looking for "/rustc/" followed by 40 hex characters.
func hasRustcPath(r io.Reader, limit int64) (bool, error) {
	r = io.LimitReader(r, limit)
	buf := make([]byte, rustScanChunk)
	keep := 0
	for {
		n, err := r.Read(buf[keep:])
		end := keep + n
		if containsRustcPath(buf[:end]) {
			return true, nil
		}
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// Carry the tail over so a marker split across two reads is still found.
		keep = min(end, rustcMarkLen-1)
		copy(buf, buf[end-keep:end])
	}
}

func containsRustcPath(b []byte) bool {
	for {
		i := bytes.Index(b, rustcPrefix)
		if i < 0 {
			return false
		}
		rest := b[i+len(rustcPrefix):]
		if len(rest) >= rustcHexLen && isHex(rest[:rustcHexLen]) {
			return true
		}
		b = b[i+1:]
	}
}

func isHex(b []byte) bool {
	for _, c := range b {
		switch {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
		default:
			return false
		}
	}
	return true
}
