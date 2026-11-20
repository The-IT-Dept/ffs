package nodegroup

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestFingerprint_Golden(t *testing.T) {
	ssl := model.Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.13-1", Arch: "amd64", Path: "/var/lib/dpkg/status"}
	ssl2 := ssl
	ssl2.Path = "/var/lib/dpkg/status.d/openssl" // Path is ignored; the line is written once
	ctd := model.Package{Ecosystem: "go-module", Name: "github.com/containerd/containerd/v2", Version: "v2.2.1", Path: "/usr/bin/containerd"}
	in := FingerprintInput{Packages: []model.Package{ctd, ssl, ssl2},
		Kernel:        &model.NodeKernel{Release: "7.0.0-34-generic", Package: "linux-image-7.0.0-34-generic", Version: "7.0.0-34.34", SourceName: "linux"},
		KernelRelease: "7.0.0-34-generic", RuntimeVersion: "containerd://2.2.1"}
	// sha256 of these lines, sorted and joined by "\n":
	//   kernel\t7.0.0-34-generic\tlinux-image-7.0.0-34-generic\t7.0.0-34.34
	//   pkg\tdeb\topenssl\t3.0.13-1\tamd64
	//   pkg\tgo-module\tgithub.com/containerd/containerd/v2\tv2.2.1\t
	//   runtime\tcontainerd://2.2.1
	const golden = "0ebc2861a1a4bda58f12243404a27150569a7a2305976d1a4c63a182363aa625"
	require.Equal(t, golden, Fingerprint(in))
	in.Packages = []model.Package{ssl, ctd} // order and duplicates do not matter
	require.Equal(t, golden, Fingerprint(in))
	for name, mut := range map[string]func(*FingerprintInput){
		"version": func(f *FingerprintInput) {
			f.Packages = []model.Package{ctd, {Ecosystem: "deb", Name: "openssl", Version: "3.0.13-2", Arch: "amd64"}}
		},
		"arch": func(f *FingerprintInput) {
			f.Packages = []model.Package{ctd, {Ecosystem: "deb", Name: "openssl", Version: "3.0.13-1", Arch: "arm64"}}
		},
		"runtime": func(f *FingerprintInput) { f.RuntimeVersion = "containerd://2.2.2" },
		"release": func(f *FingerprintInput) { f.KernelRelease = "7.0.0-38-generic" },
		"kernel":  func(f *FingerprintInput) { f.Kernel = nil },
	} {
		c := in
		mut(&c)
		require.NotEqual(t, golden, Fingerprint(c), name)
	}
}
