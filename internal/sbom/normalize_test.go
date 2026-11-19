package sbom

import (
	"testing"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

const testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// testDoc builds an image SBOM holding pkgs on release, round-tripped through syft-json the way
// stored SBOMs are read back.
func testDoc(t *testing.T, release *linux.Release, mutate func(*syftsbom.SBOM), pkgs ...pkg.Package) *syftsbom.SBOM {
	t.Helper()
	for i := range pkgs {
		pkgs[i].SetID()
	}
	doc := &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages:          pkg.NewCollection(pkgs...),
			LinuxDistribution: release,
		},
		Source:     source.Description{ID: "src", Name: "app", Metadata: source.ImageMetadata{UserInput: "app"}},
		Descriptor: syftsbom.Descriptor{Name: "syft", Version: "1.57.2"},
	}
	if mutate != nil {
		mutate(doc)
	}
	b, err := EncodeSyftJSON(doc)
	require.NoError(t, err)
	out, err := DecodeSyftJSON(b)
	require.NoError(t, err)
	return out
}

func at(path, layer string) file.LocationSet {
	return file.NewLocationSet(file.NewLocationFromCoordinates(file.Coordinates{RealPath: path, FileSystemID: layer}))
}

func byName(t *testing.T, pkgs []model.Package, name string) model.Package {
	t.Helper()
	for _, p := range pkgs {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("package %s not normalised", name)
	return model.Package{}
}

func syftIDOf(t *testing.T, doc *syftsbom.SBOM, name string) string {
	t.Helper()
	for _, p := range doc.Artifacts.Packages.Sorted() {
		if p.Name == name {
			return string(p.ID())
		}
	}
	t.Fatalf("package %s not in the SBOM", name)
	return ""
}

var (
	bookworm = &linux.Release{ID: "debian", VersionID: "12", VersionCodename: "bookworm"}
	alpine   = &linux.Release{ID: "alpine", VersionID: "3.20.3"}
	rhel     = &linux.Release{ID: "rhel", VersionID: "9.4"}
)

func TestNormalize_DebSourceAndDistro(t *testing.T) {
	dpkg := file.NewLocationSet(file.NewLocationFromCoordinates(file.Coordinates{RealPath: "/var/lib/dpkg/status", FileSystemID: "sha256:l1"}))
	doc := testDoc(t, bookworm, nil,
		pkg.Package{Name: "libssl3", Version: "3.0.15-1~deb12u1", Type: pkg.DebPkg, Locations: dpkg,
			Metadata: pkg.DpkgDBEntry{Package: "libssl3", Source: "openssl", Version: "3.0.15-1~deb12u1", Architecture: "amd64"}},
		pkg.Package{Name: "tzdata", Version: "2024a-0+deb12u1", Type: pkg.DebPkg, Locations: dpkg,
			Metadata: pkg.DpkgDBEntry{Package: "tzdata", Version: "2024a-0+deb12u1", Architecture: "all"}},
		pkg.Package{Name: "libc6", Version: "2.36-9+deb12u4+b1", Type: pkg.DebPkg, Locations: dpkg,
			Metadata: pkg.DpkgDBEntry{Package: "libc6", Source: "glibc (2.36-9+deb12u4)", Version: "2.36-9+deb12u4+b1", Architecture: "amd64"}},
		pkg.Package{Name: "libfoo", Version: "1:2.3-4", Type: pkg.DebPkg, Locations: dpkg,
			Metadata: pkg.DpkgDBEntry{Package: "libfoo", Version: "1:2.3-4", Architecture: "arm64"}},
	)
	pkgs, _ := Normalize(testDigest, doc)
	require.Len(t, pkgs, 4)

	ssl := byName(t, pkgs, "libssl3")
	want := model.Package{
		ImageDigest:   testDigest,
		Ecosystem:     "deb",
		Distro:        &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"},
		Name:          "libssl3",
		Version:       "3.0.15-1~deb12u1",
		Arch:          "amd64",
		SourceName:    "openssl",
		SourceVersion: "3.0.15-1~deb12u1",
		Path:          "/var/lib/dpkg/status",
		Layer:         "sha256:l1",
		SyftID:        syftIDOf(t, doc, "libssl3"),
	}
	want.ID = model.PackageID(testDigest, want)
	require.NotEmpty(t, ssl.SyftID)
	require.Equal(t, want, ssl)

	tz := byName(t, pkgs, "tzdata")
	require.Equal(t, "tzdata", tz.SourceName)
	require.Equal(t, "2024a-0+deb12u1", tz.SourceVersion)
	require.Empty(t, tz.Epoch)

	libc := byName(t, pkgs, "libc6")
	require.Equal(t, "glibc", libc.SourceName)
	require.Equal(t, "2.36-9+deb12u4", libc.SourceVersion)

	foo := byName(t, pkgs, "libfoo")
	require.Equal(t, "1", foo.Epoch)
	require.Equal(t, "arm64", foo.Arch)
}

func TestNormalize_ApkOriginAndRpmSource(t *testing.T) {
	apk := testDoc(t, alpine, nil, pkg.Package{
		Name: "libcrypto3", Version: "3.3.2-r0", Type: pkg.ApkPkg, Locations: at("/lib/apk/db/installed", "sha256:a1"),
		Metadata: pkg.ApkDBEntry{Package: "libcrypto3", OriginPackage: "openssl", Version: "3.3.2-r0", Architecture: "x86_64"},
	})
	pkgs, _ := Normalize(testDigest, apk)
	require.Len(t, pkgs, 1)
	require.Equal(t, "openssl", pkgs[0].SourceName)
	require.Equal(t, "3.3.2-r0", pkgs[0].SourceVersion)
	require.Equal(t, &model.Distro{ID: "alpine", VersionID: "3.20.3"}, pkgs[0].Distro)

	epoch := 1
	rpm := testDoc(t, rhel, nil, pkg.Package{
		Name: "openssl-libs", Version: "1:3.0.7-27.el9", Type: pkg.RpmPkg, Locations: at("/var/lib/rpm/rpmdb.sqlite", "sha256:r1"),
		Metadata: pkg.RpmDBEntry{Name: "openssl-libs", Version: "3.0.7", Release: "27.el9", Epoch: &epoch, Arch: "x86_64",
			SourceRpm: "openssl-3.0.7-27.el9.src.rpm"},
	})
	pkgs, _ = Normalize(testDigest, rpm)
	require.Len(t, pkgs, 1)
	require.Equal(t, "openssl", pkgs[0].SourceName)
	require.Equal(t, "3.0.7-27.el9", pkgs[0].SourceVersion)
	require.Equal(t, "1", pkgs[0].Epoch)
	require.Equal(t, &model.Distro{ID: "rhel", VersionID: "9.4"}, pkgs[0].Distro)

	name, version := SourceRPMName("python3.11-3.11.7-1.el9.src.rpm")
	require.Equal(t, "python3.11", name)
	require.Equal(t, "3.11.7-1.el9", version)
	name, version = SourceRPMName("")
	require.Empty(t, name)
	require.Empty(t, version)
}

func TestNormalize_ClassifierAndStdlib(t *testing.T) {
	classified := func(class string) pkg.BinarySignature {
		return pkg.BinarySignature{Matches: []pkg.ClassifierMatch{{Classifier: class, Location: file.NewLocation("/usr/local/bin/x")}}}
	}
	cpe23 := cpe.Must("cpe:2.3:a:php:php:8.3.13:*:*:*:*:*:*:*", cpe.GeneratedSource)
	doc := testDoc(t, bookworm, nil,
		pkg.Package{Name: "php-cli", Version: "8.3.13", Type: pkg.BinaryPkg, FoundBy: "php-interpreter-cataloger",
			Locations: at("/usr/local/bin/php", "sha256:p1"), PURL: "pkg:generic/php@8.3.13", CPEs: []cpe.CPE{cpe23},
			Metadata: classified("php-cli-binary")},
		pkg.Package{Name: "node", Version: "22.11.0", Type: pkg.BinaryPkg, FoundBy: "binary-classifier-cataloger",
			Locations: at("/usr/local/bin/node", "sha256:n1"), Metadata: classified("nodejs-binary")},
		pkg.Package{Name: "stdlib", Version: "go1.23.2", Type: pkg.GoModulePkg, Locations: at("/usr/bin/app", "sha256:g1")},
		pkg.Package{Name: "left-pad", Version: "1.3.0", Type: pkg.NpmPkg, Locations: at("/app/node_modules/left-pad/package.json", "sha256:j1")},
	)
	pkgs, _ := Normalize(testDigest, doc)
	require.Len(t, pkgs, 4)

	php := byName(t, pkgs, "php-cli")
	require.Equal(t, "php-cli-binary", php.Classifier)
	require.Equal(t, "pkg:generic/php@8.3.13", php.PURL)
	require.Equal(t, []string{"cpe:2.3:a:php:php:8.3.13:*:*:*:*:*:*:*"}, php.CPEs)
	require.Equal(t, "/usr/local/bin/php", php.Path)
	require.Equal(t, "sha256:p1", php.Layer)
	require.Nil(t, php.Distro)

	require.Equal(t, "nodejs-binary", byName(t, pkgs, "node").Classifier)

	std := byName(t, pkgs, "stdlib")
	require.True(t, std.GoStdlib)
	require.Nil(t, std.Distro)

	npm := byName(t, pkgs, "left-pad")
	require.False(t, npm.GoStdlib)
	require.Nil(t, npm.Distro)
	require.Empty(t, npm.Classifier)
}

func TestCoverageOf(t *testing.T) {
	const unattributed = "unknowns-labeler: no package identified in executable file"
	elf := file.Executable{Format: file.ELF}
	coords := func(p string) file.Coordinates { return file.Coordinates{RealPath: p, FileSystemID: "sha256:l1"} }
	doc := testDoc(t, bookworm, func(d *syftsbom.SBOM) {
		d.Artifacts.Unknowns = map[file.Coordinates][]string{
			coords("/usr/bin/a"):     {unattributed},
			coords("/usr/bin/b"):     {unattributed},
			coords("/usr/bin/rusty"): {unattributed, UnknownRustNoAuditable},
			coords("/opt/mac/tool"):  {unattributed},
		}
		d.Artifacts.Executables = map[file.Coordinates]file.Executable{
			coords("/usr/bin/a"):     elf,
			coords("/usr/bin/b"):     elf,
			coords("/usr/bin/rusty"): elf,
			coords("/opt/mac/tool"):  {Format: file.MachO},
		}
	})
	require.Equal(t, model.Coverage{
		UnattributedELF:      3,
		RustWithoutAuditable: 1,
		Notes:                []string{"3 executables not attributed to any package", "1 Rust binaries built without cargo-auditable"},
	}, CoverageOf(doc))

	_, cov := Normalize(testDigest, doc)
	require.Equal(t, 3, cov.UnattributedELF)

	require.Equal(t, model.Coverage{}, CoverageOf(testDoc(t, bookworm, nil)))
}

func TestConfigUser(t *testing.T) {
	withSource := func(m any) func(*syftsbom.SBOM) {
		return func(d *syftsbom.SBOM) { d.Source.Metadata = m }
	}
	doc := testDoc(t, bookworm, withSource(source.ImageMetadata{UserInput: "app", RawConfig: []byte(`{"config":{"User":"65532:65532"}}`)}))
	require.Equal(t, "65532:65532", ConfigUser(doc))

	doc = testDoc(t, bookworm, withSource(source.ImageMetadata{UserInput: "app", RawConfig: []byte(`{"config":{"Env":["A=1"]}}`)}))
	require.Equal(t, "", ConfigUser(doc))

	doc = testDoc(t, nil, withSource(source.DirectoryMetadata{Path: "/src"}))
	require.Equal(t, "", ConfigUser(doc))
}
