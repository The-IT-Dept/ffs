package nodegroup

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

var (
	fpUbuntu = &model.Distro{ID: "ubuntu", VersionID: "26.04", Codename: "resolute"}
	fpSSL    = model.Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.13-1", Arch: "amd64", Distro: fpUbuntu,
		SourceName: "openssl", SourceVersion: "3.0.13-1", PURL: "pkg:deb/ubuntu/openssl@3.0.13-1?arch=amd64&distro=ubuntu-26.04",
		CPEs: []string{"cpe:2.3:a:openssl:openssl:3.0.13-1:*:*:*:*:*:*:*"}, Path: "/var/lib/dpkg/status"}
	fpCtd = model.Package{Ecosystem: "go-module", Name: "github.com/containerd/containerd/v2", Version: "v2.2.1",
		PURL: "pkg:golang/github.com/containerd/containerd/v2@v2.2.1", Path: "/usr/bin/containerd"}
)

func fpInput(pkgs ...model.Package) FingerprintInput {
	return FingerprintInput{Packages: pkgs, Distro: fpUbuntu,
		Kernel:        &model.NodeKernel{Release: "7.0.0-34-generic", Package: "linux-image-7.0.0-34-generic", Version: "7.0.0-34.34", SourceName: "linux"},
		KernelRelease: "7.0.0-34-generic", RuntimeVersion: "containerd://2.2.1"}
}

func TestFingerprint_Golden(t *testing.T) {
	ssl2 := fpSSL
	ssl2.Path = "/var/lib/dpkg/status.d/openssl" // Path is ignored; the line is written once
	in := fpInput(fpCtd, fpSSL, ssl2)
	// sha256 of these lines, sorted and joined by "\n":
	//   distro\tubuntu\t26.04
	//   kernel\t7.0.0-34-generic\tlinux-image-7.0.0-34-generic\t7.0.0-34.34
	//   pkg\tdeb\topenssl\t3.0.13-1\tamd64\t\tubuntu 26.04\topenssl\t3.0.13-1\tpkg:deb/ubuntu/openssl@3.0.13-1?arch=amd64&distro=ubuntu-26.04\tcpe:2.3:a:openssl:openssl:3.0.13-1:*:*:*:*:*:*:*
	//   pkg\tgo-module\tgithub.com/containerd/containerd/v2\tv2.2.1\t\t\t\t\t\tpkg:golang/github.com/containerd/containerd/v2@v2.2.1\t
	//   runtime\tcontainerd://2.2.1
	const golden = "0518034a6d4dbacbc68abf19c80abd3bc6838b1ad756b50681d04ca723875c57"
	require.Equal(t, golden, Fingerprint(in))
	in.Packages = []model.Package{fpSSL, fpCtd} // order and duplicates do not matter
	require.Equal(t, golden, Fingerprint(in))
	for name, mut := range map[string]func(*FingerprintInput){
		"version": func(f *FingerprintInput) { f.Packages[0].Version = "3.0.13-2" },
		"arch":    func(f *FingerprintInput) { f.Packages[0].Arch = "arm64" },
		"runtime": func(f *FingerprintInput) { f.RuntimeVersion = "containerd://2.2.2" },
		"release": func(f *FingerprintInput) { f.KernelRelease = "7.0.0-38-generic" },
		"kernel":  func(f *FingerprintInput) { f.Kernel = nil },
	} {
		c := fpInput(fpSSL, fpCtd)
		mut(&c)
		require.NotEqual(t, golden, Fingerprint(c), name)
	}
}

// TestFingerprint_HashesMatcherFields: every field the matcher reads changes the fingerprint, so a host
// document stripped of its matching metadata cannot join the group of hosts that report it in full.
func TestFingerprint_HashesMatcherFields(t *testing.T) {
	full := Fingerprint(fpInput(fpSSL, fpCtd))
	again := fpInput(fpCtd, fpSSL)
	require.Equal(t, full, Fingerprint(again), "the same SBOM gives the same fingerprint")
	cpes := fpSSL
	cpes.CPEs = []string{"cpe:2.3:a:openssl:openssl:3.0.13-1:*:*:*:*:*:*:*", "cpe:2.3:a:openssl_project:openssl:3.0.13-1:*:*:*:*:*:*:*"}
	reordered := cpes
	reordered.CPEs = []string{cpes.CPEs[1], cpes.CPEs[0]}
	require.Equal(t, Fingerprint(fpInput(cpes, fpCtd)), Fingerprint(fpInput(reordered, fpCtd)), "CPE order does not matter")

	for name, mut := range map[string]func(p *model.Package, in *FingerprintInput){
		"no PURL": func(p *model.Package, _ *FingerprintInput) { p.PURL = "" },
		"no CPEs": func(p *model.Package, _ *FingerprintInput) { p.CPEs = nil },
		"other CPE": func(p *model.Package, _ *FingerprintInput) {
			p.CPEs = []string{"cpe:2.3:a:other:openssl:3.0.13-1:*:*:*:*:*:*:*"}
		},
		"no package distro": func(p *model.Package, _ *FingerprintInput) { p.Distro = nil },
		"other distro version": func(p *model.Package, _ *FingerprintInput) {
			p.Distro = &model.Distro{ID: "ubuntu", VersionID: "24.04"}
		},
		"no source name":    func(p *model.Package, _ *FingerprintInput) { p.SourceName = "" },
		"no source version": func(p *model.Package, _ *FingerprintInput) { p.SourceVersion = "" },
		"epoch":             func(p *model.Package, _ *FingerprintInput) { p.Epoch = "1" },
		"no host distro":    func(_ *model.Package, in *FingerprintInput) { in.Distro = nil },
	} {
		ssl := fpSSL
		in := fpInput()
		mut(&ssl, &in)
		in.Packages = []model.Package{ssl, fpCtd}
		require.NotEqual(t, full, Fingerprint(in), name)
	}

	// Dropping a Go module's PURL changes it too.
	ctd := fpCtd
	ctd.PURL = ""
	require.NotEqual(t, full, Fingerprint(fpInput(fpSSL, ctd)))
}
