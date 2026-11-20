package catalog_test

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/catalog"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/sbom"
)

// TestCatalog_OCIDirSource catalogues an OCI layout, as the node agent stages a side-loaded image,
// with the same SBOM settings as a registry image: the image config is kept.
func TestCatalog_OCIDirSource(t *testing.T) {
	img := layerImage(t, "65532:65532", debianLayer...)
	dir := filepath.Join(t.TempDir(), "oci")
	p, err := layout.Write(dir, empty.Index)
	require.NoError(t, err)
	require.NoError(t, p.AppendImage(img, layout.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"})))
	digest, err := img.Digest()
	require.NoError(t, err)
	t.Setenv("TMPDIR", t.TempDir())

	resp, err := catalog.Catalog(ctx, sbom.CatalogRequest{Source: sbom.CatalogSourceOCIDir, Path: dir, Platform: "linux/amd64",
		MaxBytes: 1 << 30, TimeoutSeconds: 60})
	require.NoError(t, err)
	requireDebianSBOM(t, digest.String(), resp)

	_, err = catalog.Catalog(ctx, sbom.CatalogRequest{Source: sbom.CatalogSourceOCIDir, Path: dir, Platform: "linux/arm64",
		MaxBytes: 1 << 30, TimeoutSeconds: 60})
	var we *catalog.WorkError
	require.ErrorAs(t, err, &we)
	require.Equal(t, sbom.KindFailed, we.Kind, we.Msg)
}

// TestCatalog_HostDirSource catalogues a staged copy of host inputs: the package database and the Go
// modules of host binaries, at their host paths, and nothing else.
func TestCatalog_HostDirSource(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644)) //nolint:gosec // G306: test fixture
	}
	write("etc/os-release", "PRETTY_NAME=\"Ubuntu 26.04 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\nID=ubuntu\nID_LIKE=debian\n")
	write("var/lib/dpkg/status", "Package: libssl3\nStatus: install ok installed\nPriority: optional\nSection: libs\n"+
		"Installed-Size: 6000\nMaintainer: Ubuntu Developers <ubuntu-devel-discuss@example.org>\nArchitecture: amd64\n"+
		"Multi-Arch: same\nSource: openssl\nVersion: 3.0.13-0ubuntu3.4\nDescription: Secure Sockets Layer toolkit\n\n"+
		"Package: bash\nStatus: install ok installed\nPriority: required\nSection: shells\nInstalled-Size: 1800\n"+
		"Maintainer: Ubuntu Developers <ubuntu-devel-discuss@example.org>\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu4\n"+
		"Description: GNU Bourne Again SHell\n\n")
	write("opt/app/node_modules/left-pad/package.json", `{"name":"left-pad","version":"1.3.0"}`)
	self, err := os.Executable()
	require.NoError(t, err)
	copyFile(t, self, filepath.Join(dir, "usr/bin/ffs-probe"))
	t.Setenv("TMPDIR", t.TempDir())

	resp, err := catalog.Catalog(ctx, sbom.CatalogRequest{Source: sbom.CatalogSourceHostDir, Path: dir, MaxBytes: 1 << 30, TimeoutSeconds: 60})
	require.NoError(t, err)
	doc, err := sbom.DecodeSyftJSON(resp.SyftJSON)
	require.NoError(t, err)
	for c, entries := range doc.Artifacts.Unknowns {
		// Syft reads a Go binary's crypto settings from ELF only, so the probe (this test binary) is
		// noted when the test runs off Linux. Host binaries are ELF.
		if runtime.GOOS != "linux" && c.RealPath == "/usr/bin/ffs-probe" && !slices.ContainsFunc(entries, func(e string) bool {
			return !strings.HasPrefix(e, "go-module-binary-cataloger: unable to read golang version info")
		}) {
			continue
		}
		t.Errorf("unknowns reported for %s: %v", c.RealPath, entries)
	}
	require.Zero(t, resp.Coverage)

	pkgs, _ := sbom.Normalize("nodegroup:test", doc)
	debs := map[string]model.Package{}
	goProbe := false
	for _, p := range pkgs {
		require.NotEqual(t, "npm", p.Ecosystem, "only the host catalogers run")
		switch p.Ecosystem {
		case "deb":
			debs[p.Name] = p
		case "go-module":
			goProbe = goProbe || p.Path == "/usr/bin/ffs-probe"
		}
	}
	require.Contains(t, debs, "libssl3")
	require.Contains(t, debs, "bash")
	for _, p := range debs {
		require.NotNil(t, p.Distro, p.Name)
		require.Equal(t, "ubuntu", p.Distro.ID)
		require.Equal(t, "26.04", p.Distro.VersionID)
	}
	require.Equal(t, "openssl", debs["libssl3"].SourceName)
	require.True(t, goProbe, "the binary's Go modules are located at its host path, not under the staging directory")
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(to), 0o750))
	in, err := os.Open(from) //nolint:gosec // G304: the test binary
	require.NoError(t, err)
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) //nolint:gosec // G302: an executable fixture
	require.NoError(t, err)
	_, err = io.Copy(out, in)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}
