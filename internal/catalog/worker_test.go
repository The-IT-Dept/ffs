package catalog

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/file"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/sbom"
)

const rustcMarker = "/rustc/0123456789abcdef0123456789abcdef01234567/library/core/src/panicking.rs"

// zeros is an endless reader of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestRustDetection(t *testing.T) {
	dir := t.TempDir()
	elf := func(body string) []byte { return append([]byte("\x7fELF\x02\x01\x01"), body...) }
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rusty"), elf("padding "+rustcMarker+" more"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plain"), elf("built by gcc /rustc/not-a-commit"), 0o600))

	src, err := directorysource.NewFromPath(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Close() })

	const unattributed = "unknowns-labeler: no package identified in executable file"
	rusty, plain := file.Coordinates{RealPath: "/rusty"}, file.Coordinates{RealPath: "/plain"}
	doc := &syftsbom.SBOM{Artifacts: syftsbom.Artifacts{
		Unknowns:    map[file.Coordinates][]string{rusty: {unattributed}, plain: {unattributed}},
		Executables: map[file.Coordinates]file.Executable{rusty: {Format: file.ELF}, plain: {Format: file.ELF}},
	}}
	require.NoError(t, markRust(doc, src))
	require.Equal(t, []string{unattributed, sbom.UnknownRustNoAuditable}, doc.Artifacts.Unknowns[rusty])
	require.Equal(t, []string{unattributed}, doc.Artifacts.Unknowns[plain])
	require.Equal(t, 1, sbom.CoverageOf(doc).RustWithoutAuditable)

	// The scan reads at most 256 MiB per file, and finds a marker split across two reads.
	found, err := hasRustcPath(io.MultiReader(io.LimitReader(zeros{}, maxRustScan-int64(len(rustcMarker))), strings.NewReader(rustcMarker)), maxRustScan)
	require.NoError(t, err)
	require.True(t, found, "marker inside the limit")
	found, err = hasRustcPath(io.MultiReader(io.LimitReader(zeros{}, maxRustScan), strings.NewReader(rustcMarker)), maxRustScan)
	require.NoError(t, err)
	require.False(t, found, "marker past the limit")
	split := make([]byte, rustScanChunk+len(rustcMarker))
	copy(split[rustScanChunk-10:], rustcMarker)
	found, err = hasRustcPath(bytes.NewReader(split), maxRustScan)
	require.NoError(t, err)
	require.True(t, found, "marker across a chunk boundary")
	found, err = hasRustcPath(bytes.NewReader([]byte("/rustc/0123456789abcdef")), maxRustScan)
	require.NoError(t, err)
	require.False(t, found, "short hash")
}
