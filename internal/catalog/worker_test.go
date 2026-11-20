package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/anchore/syft/syft/file"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
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

// TestWorkError_RegistryAndNetworkErrorsNotCounted: only failures count toward quarantine, so
// registry refusals, rate limits, server errors and network failures each get their own kind, also
// when stereoscope has flattened them to text with %+v.
func TestWorkError_RegistryAndNetworkErrorsNotCounted(t *testing.T) {
	get := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "ghcr.io", Path: "/v2/a/b/manifests/x"}}
	te := func(status int, code transport.ErrorCode) *transport.Error {
		e := &transport.Error{StatusCode: status, Request: get}
		if code != "" {
			e.Errors = []transport.Diagnostic{{Code: code, Message: "detail"}}
		}
		return e
	}
	// stereoscope's wrapping, which keeps only the text
	flat := func(err error) error { return fmt.Errorf("failed to get image descriptor from registry: %+v", err) } //nolint:errorlint // the point is a non-wrapping verb
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	dns := &net.DNSError{Err: "no such host", Name: "registry.local", IsNotFound: true}

	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"flattened 429", flat(te(http.StatusTooManyRequests, transport.TooManyRequestsErrorCode)), sbom.KindRateLimited},
		{"flattened 429 without body", flat(te(http.StatusTooManyRequests, "")), sbom.KindRateLimited},
		{"flattened 401", flat(te(http.StatusUnauthorized, transport.UnauthorizedErrorCode)), sbom.KindUnauthorized},
		{"flattened 403 denied", flat(te(http.StatusForbidden, transport.DeniedErrorCode)), sbom.KindUnauthorized},
		{"flattened 404", flat(te(http.StatusNotFound, transport.ManifestUnknownErrorCode)), sbom.KindNotFound},
		{"flattened 502", flat(te(http.StatusBadGateway, "")), sbom.KindUnavailable},
		{"typed 503", fmt.Errorf("pull: %w", te(http.StatusServiceUnavailable, "")), sbom.KindUnavailable},
		{"typed refused", &url.Error{Op: "Get", URL: "https://ghcr.io/v2/", Err: dial}, sbom.KindUnavailable},
		{"typed dns", fmt.Errorf("ping: %w", dns), sbom.KindUnavailable},
		{"flattened dns", flat(&url.Error{Op: "Get", URL: "https://registry.local/v2/", Err: dns}), sbom.KindUnavailable},
		{"flattened refused", flat(&url.Error{Op: "Get", URL: "https://ghcr.io/v2/", Err: dial}), sbom.KindUnavailable},
		{"corrupt layer", errors.New("unpacking layer: gzip: invalid header"), sbom.KindFailed},
		{"permission", errors.New("open /tmp/x: permission denied"), sbom.KindFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, workError(tc.err).Kind, tc.err.Error())
		})
	}
}
