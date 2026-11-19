package osv_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

func TestEcosystems_Mapping(t *testing.T) {
	distro := func(id, version string) *model.Distro { return &model.Distro{ID: id, VersionID: version} }
	for _, tc := range []struct {
		name       string
		pkg        model.Package
		eco        string // "" = not matched
		bucket     string // BucketFor without chainguard
		cgBucket   string // BucketFor with chainguard
		sourceJoin bool
		syftType   string
		index      []string
	}{
		{"debian source join", model.Package{Ecosystem: "deb", Distro: distro("debian", "12"), Name: "libssl3", SourceName: "openssl"},
			"Debian:12", "Debian", "Debian", true, "deb", []string{"openssl"}},
		{"debian no source", model.Package{Ecosystem: "deb", Distro: distro("debian", "12"), Name: "bash"},
			"Debian:12", "Debian", "Debian", true, "deb", []string{"bash"}},
		{"ubuntu", model.Package{Ecosystem: "deb", Distro: distro("ubuntu", "24.04"), Name: "libssl3t64", SourceName: "openssl"},
			"Ubuntu:24.04", "Ubuntu", "Ubuntu", true, "deb", []string{"openssl"}},
		{"alpine origin", model.Package{Ecosystem: "apk", Distro: distro("alpine", "3.20.3"), Name: "libcrypto3", SourceName: "openssl"},
			"Alpine:v3.20", "Alpine", "Alpine", true, "apk", []string{"openssl"}},
		{"wolfi", model.Package{Ecosystem: "apk", Distro: distro("wolfi", "20230201"), Name: "glibc"},
			"Wolfi", "", "Wolfi", true, "apk", []string{"glibc"}},
		{"chainguard", model.Package{Ecosystem: "apk", Distro: distro("chainguard", "20230214"), Name: "openssl"},
			"Chainguard", "", "Chainguard", true, "apk", []string{"openssl"}},
		{"almalinux", model.Package{Ecosystem: "rpm", Distro: distro("almalinux", "9.4"), Name: "openssl-libs", SourceName: "openssl"},
			"AlmaLinux:9", "AlmaLinux", "AlmaLinux", false, "rpm", []string{"openssl-libs"}},
		{"rocky", model.Package{Ecosystem: "rpm", Distro: distro("rocky", "9.3"), Name: "curl"},
			"Rocky Linux:9", "Rocky Linux", "Rocky Linux", false, "rpm", []string{"curl"}},
		{"pypi in a debian image", model.Package{Ecosystem: "python", Distro: distro("debian", "12"), Name: "Foo_Bar.baz"},
			"PyPI", "PyPI", "PyPI", false, "python", []string{"foo-bar-baz"}},
		{"npm", model.Package{Ecosystem: "npm", Name: "@babel/core"}, "npm", "npm", "npm", false, "npm", []string{"@babel/core"}},
		{"go module", model.Package{Ecosystem: "go-module", Name: "golang.org/x/net"}, "Go", "Go", "Go", false, "go-module", []string{"golang.org/x/net"}},
		{"go stdlib", model.Package{Ecosystem: "go-module", Name: "stdlib", GoStdlib: true}, "Go", "Go", "Go", false, "go-module", []string{"stdlib"}},
		{"maven", model.Package{Ecosystem: "java-archive", Name: "log4j-core",
			PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"},
			"Maven", "Maven", "Maven", false, "java-archive", []string{"org.apache.logging.log4j:log4j-core"}},
		{"maven without purl", model.Package{Ecosystem: "java-archive", Name: "app"}, "Maven", "Maven", "Maven", false, "java-archive", nil},
		{"rubygems", model.Package{Ecosystem: "gem", Name: "rack"}, "RubyGems", "RubyGems", "RubyGems", false, "gem", []string{"rack"}},
		{"crates", model.Package{Ecosystem: "rust-crate", Name: "tokio"}, "crates.io", "crates.io", "crates.io", false, "rust-crate", []string{"tokio"}},
		{"nuget", model.Package{Ecosystem: "dotnet", Name: "Newtonsoft.Json"}, "NuGet", "NuGet", "NuGet", false, "dotnet", []string{"Newtonsoft.Json"}},
		{"packagist", model.Package{Ecosystem: "php-composer", Name: "guzzlehttp/guzzle"},
			"Packagist", "Packagist", "Packagist", false, "php-composer", []string{"guzzlehttp/guzzle"}},
		{"hex", model.Package{Ecosystem: "hex", Name: "plug"}, "Hex", "Hex", "Hex", false, "hex", []string{"plug"}},
		{"pub", model.Package{Ecosystem: "dart-pub", Name: "http"}, "Pub", "Pub", "Pub", false, "dart-pub", []string{"http"}},
		{"rpm on rhel", model.Package{Ecosystem: "rpm", Distro: distro("rhel", "9.4"), Name: "openssl"}, "", "", "", false, "", nil},
		{"rpm on sles", model.Package{Ecosystem: "rpm", Distro: distro("sles", "15.5"), Name: "openssl"}, "", "", "", false, "", nil},
		{"rpm on amzn", model.Package{Ecosystem: "rpm", Distro: distro("amzn", "2023"), Name: "openssl"}, "", "", "", false, "", nil},
		{"rpm on ol", model.Package{Ecosystem: "rpm", Distro: distro("ol", "9"), Name: "openssl"}, "", "", "", false, "", nil},
		{"binary", model.Package{Ecosystem: "binary", Name: "php", Classifier: "php-cli-binary"}, "", "", "", false, "", nil},
		{"debian without version", model.Package{Ecosystem: "deb", Distro: distro("debian", ""), Name: "bash"}, "", "", "", false, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eco, ok := osv.PackageEcosystem(tc.pkg)
			require.Equal(t, tc.eco, eco)
			require.Equal(t, tc.eco != "", ok)

			var k store.EcosystemKey
			k.Ecosystem = tc.pkg.Ecosystem
			if tc.pkg.Distro != nil {
				k.DistroID, k.DistroVersion = tc.pkg.Distro.ID, tc.pkg.Distro.VersionID
			}
			require.Equal(t, tc.bucket, osv.BucketFor(k, false))
			require.Equal(t, tc.cgBucket, osv.BucketFor(k, true))
			require.Equal(t, tc.index, osv.PackageIndexNames(tc.pkg))
			if tc.eco != "" {
				b := osv.BucketOf(tc.eco)
				require.Equal(t, tc.sourceJoin, osv.SourceJoin(b))
				require.Equal(t, tc.syftType, osv.SyftType(b))
			}
		})
	}

	require.Equal(t, "Ubuntu:24.04", osv.NormalizeRecordEcosystem("Ubuntu:24.04:LTS"))
	require.Equal(t, "Ubuntu:24.10", osv.NormalizeRecordEcosystem("Ubuntu:24.10"))
	require.Equal(t, "Ubuntu:Pro:24.04:LTS", osv.NormalizeRecordEcosystem("Ubuntu:Pro:24.04:LTS"))
	require.Equal(t, "Alpine:v3.20", osv.NormalizeRecordEcosystem("Alpine:v3.20"))
	require.Equal(t, "Debian:12", osv.NormalizeRecordEcosystem("Debian:12"))

	require.Equal(t, "Rocky Linux", osv.BucketOf("Rocky Linux:9"))
	require.Equal(t, "PyPI", osv.BucketOf("PyPI"))
	require.Equal(t, "Ubuntu", osv.BucketOf("Ubuntu:Pro:24.04:LTS"))
	require.Empty(t, osv.SyftType(osv.BucketGIT))

	require.Equal(t, "foo-bar-baz", osv.IndexName("PyPI", "Foo_Bar.baz"))
	require.Equal(t, "foo-bar", osv.IndexName("PyPI", "foo__-.bar"))
	require.Equal(t, "org.example:lib", osv.IndexName("Maven", "org.Example:Lib"))
	require.Equal(t, "github.com/php/php-src", osv.IndexName("GIT", "https://github.com/PHP/php-src.git"))
	require.Equal(t, "Newtonsoft.Json", osv.IndexName("NuGet", "Newtonsoft.Json"))

	require.Equal(t, "github.com/php/php-src", osv.NormalizeRepo("https://github.com/PHP/php-src.git"))
	require.Equal(t, "github.com/php/php-src", osv.NormalizeRepo("https://github.com/PHP/php-src.git/"))
	require.Equal(t, "github.com/php/php-src", osv.NormalizeRepo("git://user@github.com/php/php-src"))
	require.Equal(t, "github.com/kubernetes/kubernetes", osv.NormalizeRepo("github.com/kubernetes/kubernetes"))

	for _, tc := range []struct {
		bucket, id string
		skip       bool
	}{
		{"Debian", "DEBIAN-CVE-2026-1", false}, {"Debian", "DSA-5001-1", true}, {"Debian", "DLA-4001-1", true},
		{"Debian", "DTSA-1", true}, {"Ubuntu", "UBUNTU-CVE-2026-1", false}, {"Ubuntu", "USN-7001-1", true},
		{"Ubuntu", "LSN-0100-1", true}, {"PyPI", "PYSEC-2026-1", false}, {"Alpine", "ALPINE-CVE-2026-1", false},
	} {
		require.Equal(t, tc.skip, osv.SkipID(tc.bucket, tc.id), "%s %s", tc.bucket, tc.id)
	}
}
