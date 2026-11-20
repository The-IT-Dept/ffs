package nodegroup

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func deb(name, version, source string) model.Package {
	return model.Package{Ecosystem: "deb", Name: name, Version: version, SourceName: source, Arch: "amd64"}
}

var ubuntuKernels = []model.Package{
	deb("linux-image-7.0.0-34-generic", "7.0.0-34.34", "linux"), deb("linux-modules-7.0.0-34-generic", "7.0.0-34.34", "linux"),
	deb("linux-headers-7.0.0-34", "7.0.0-34.34", "linux"), // flavourless: belongs to every 7.0.0-34-* release
	deb("linux-headers-7.0.0-34-generic", "7.0.0-34.34", "linux"),
	deb("linux-image-7.0.0-38-generic", "7.0.0-38.38", "linux"), deb("linux-modules-7.0.0-38-generic", "7.0.0-38.38", "linux"),
	deb("linux-headers-7.0.0-38", "7.0.0-38.38", "linux"),
	deb("linux-image-generic", "7.0.0.38.38", "linux-meta"), // meta package: not a kernel package
	deb("openssl", "3.0.13-1", "openssl"),
}

// debianKernels is a Debian 13 node: releases are <x.y.z>+deb13-<flavour>.
var debianKernels = []model.Package{
	deb("linux-image-6.12.41+deb13-amd64", "6.12.41-1", "linux-signed-amd64"), deb("linux-headers-6.12.41+deb13-amd64", "6.12.41-1", "linux"),
	deb("linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux-signed-amd64"), deb("linux-headers-6.12.48+deb13-amd64", "6.12.48-1", "linux"),
	deb("linux-image-amd64", "6.12.48-1", "linux-signed-amd64"), // meta package: not a kernel package
	deb("openssl", "3.5.1-1", "openssl"),
}

func rpm(name, version string) model.Package {
	return model.Package{Ecosystem: "rpm", Name: name, Version: version, Arch: "x86_64", SourceName: "kernel"}
}

// names returns the package names, in order.
func names(ps []model.Package) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func TestKernelReleaseOf(t *testing.T) {
	for _, tc := range []struct {
		p    model.Package
		want string // "" = not a kernel package
	}{
		{deb("linux-image-7.0.0-34-generic", "7.0.0-34.34", "linux"), "7.0.0-34-generic"},
		{deb("linux-image-unsigned-7.0.0-34-generic", "7.0.0-34.34", "linux"), "7.0.0-34-generic"},
		{deb("linux-modules-extra-7.0.0-34-generic", "7.0.0-34.34", "linux"), "7.0.0-34-generic"},
		{deb("linux-tools-7.0.0-34-generic", "7.0.0-34.34", "linux"), "7.0.0-34-generic"},
		{deb("linux-headers-7.0.0-34", "7.0.0-34.34", "linux"), "7.0.0-34"},
		{deb("linux-image-6.1.0-18-amd64", "6.1.76-1", "linux-signed-amd64"), "6.1.0-18-amd64"},
		{deb("linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux-signed-amd64"), "6.12.48+deb13-amd64"},
		{deb("linux-image-6.12.48+deb13-cloud-amd64", "6.12.48-1", "linux-signed-amd64"), "6.12.48+deb13-cloud-amd64"},
		{deb("linux-headers-6.12.48+deb13-amd64", "6.12.48-1", "linux"), "6.12.48+deb13-amd64"},
		{deb("linux-image-6.12.12+bpo-amd64", "6.12.12-1~bpo12+1", "linux-signed-amd64"), "6.12.12+bpo-amd64"},
		{deb("linux-image-amd64", "6.12.48-1", "linux-signed-amd64"), ""},
		{deb("linux-kbuild-6.12.48+deb13", "6.12.48-1", "linux"), ""},
		{deb("linux-image-generic", "7.0.0.34.34", "linux-meta"), ""},
		{deb("linux-libc-dev", "7.0.0-34.34", "linux"), ""},
		{deb("linux-firmware", "20260301", "linux-firmware"), ""},
		{rpm("kernel-core", "5.14.0-427.el9"), "5.14.0-427.el9.x86_64"},
		{rpm("kernel", "5.14.0-427.el9"), "5.14.0-427.el9.x86_64"},
		{rpm("kernel-modules-extra", "5.14.0-427.el9"), "5.14.0-427.el9.x86_64"},
		{rpm("kernel-core", "1:5.14.0-427.el9"), "5.14.0-427.el9.x86_64"}, // epoch dropped
		{rpm("kernel-uek-core", "5.15.0-205.149.5.1.el9uek"), "5.15.0-205.149.5.1.el9uek.x86_64"},
		{rpm("kernel-headers", "5.14.0-427.el9"), ""},
		{rpm("kernel-tools", "5.14.0-427.el9"), ""},
		{model.Package{Ecosystem: "apk", Name: "linux-lts", Version: "6.6.31-r0"}, "6.6.31-0-lts"},
		{model.Package{Ecosystem: "apk", Name: "linux-virt", Version: "6.6.31-r1"}, "6.6.31-1-virt"},
		{model.Package{Ecosystem: "apk", Name: "linux-firmware", Version: "20260301-r0"}, ""},
		{model.Package{Ecosystem: "npm", Name: "linux-image-7.0.0-34-generic", Version: "1.0.0"}, ""},
	} {
		got, ok := KernelReleaseOf(tc.p)
		require.Equal(t, tc.want != "", ok, tc.p.Name)
		require.Equal(t, tc.want, got, tc.p.Name)
	}
}

func TestKernels_OnlyRunningKernelKept(t *testing.T) {
	s := SplitKernels(ubuntuKernels, "7.0.0-34-generic")
	require.Equal(t, []string{"linux-image-7.0.0-34-generic", "linux-modules-7.0.0-34-generic", "linux-headers-7.0.0-34",
		"linux-headers-7.0.0-34-generic", "linux-image-generic", "openssl"}, names(s.Running)) // input order
	require.Equal(t, []string{"linux-image-7.0.0-38-generic", "linux-modules-7.0.0-38-generic", "linux-headers-7.0.0-38"}, names(s.Other))
	require.Equal(t, &model.NodeKernel{Release: "7.0.0-34-generic", Package: "linux-image-7.0.0-34-generic",
		Version: "7.0.0-34.34", SourceName: "linux"}, s.Kernel)

	s = SplitKernels([]model.Package{rpm("kernel", "5.14.0-427.el9"), rpm("kernel-core", "5.14.0-427.el9"),
		rpm("kernel-modules", "5.14.0-427.el9"), rpm("kernel-core", "5.14.0-503.el9"), rpm("kernel-headers", "5.14.0-503.el9")},
		"5.14.0-427.el9.x86_64")
	require.Equal(t, []string{"kernel", "kernel-core", "kernel-modules", "kernel-headers"}, names(s.Running))
	require.Equal(t, []model.Package{rpm("kernel-core", "5.14.0-503.el9")}, s.Other)
	require.Equal(t, "kernel-core", s.Kernel.Package) // preferred over the kernel meta package

	s = SplitKernels(debianKernels, "6.12.48+deb13-amd64")
	require.Equal(t, []string{"linux-image-6.12.48+deb13-amd64", "linux-headers-6.12.48+deb13-amd64", "linux-image-amd64", "openssl"},
		names(s.Running))
	require.Equal(t, []string{"linux-image-6.12.41+deb13-amd64", "linux-headers-6.12.41+deb13-amd64"}, names(s.Other))
	require.Equal(t, &model.NodeKernel{Release: "6.12.48+deb13-amd64", Package: "linux-image-6.12.48+deb13-amd64",
		Version: "6.12.48-1", SourceName: "linux-signed-amd64"}, s.Kernel)
	require.False(t, s.RebootPending)

	lts := model.Package{Ecosystem: "apk", Name: "linux-lts", Version: "6.6.31-r0", Arch: "x86_64", SourceName: "linux-lts"}
	s = SplitKernels([]model.Package{lts, {Ecosystem: "apk", Name: "musl", Version: "1.2.5-r0"}}, "6.6.31-0-lts")
	require.Empty(t, s.Other)
	require.Equal(t, &model.NodeKernel{Release: "6.6.31-0-lts", Package: "linux-lts", Version: "6.6.31-r0", SourceName: "linux-lts"}, s.Kernel)
	require.False(t, s.RebootPending)

	s = SplitKernels(ubuntuKernels, "") // osrelease unreadable: nothing is dropped
	require.Equal(t, ubuntuKernels, s.Running)
	require.Empty(t, s.Other)
	require.Nil(t, s.Kernel)
	require.False(t, s.RebootPending)
}

func TestKernels_RebootPendingWhenNewerInstalled(t *testing.T) {
	s := SplitKernels(ubuntuKernels, "7.0.0-34-generic")
	require.True(t, s.RebootPending)
	require.Equal(t, "installed kernel 7.0.0-38-generic is newer than the running kernel 7.0.0-34-generic", s.RebootReason)

	s = SplitKernels(ubuntuKernels, "7.0.0-38-generic") // after the reboot
	require.False(t, s.RebootPending)
	require.Empty(t, s.RebootReason)
	require.Equal(t, []string{"linux-image-7.0.0-34-generic", "linux-modules-7.0.0-34-generic", "linux-headers-7.0.0-34",
		"linux-headers-7.0.0-34-generic"}, names(s.Other))

	s = SplitKernels([]model.Package{rpm("kernel-core", "5.14.0-427.el9"), rpm("kernel-core", "5.14.0-503.el9")}, "5.14.0-427.el9.x86_64")
	require.Equal(t, "installed kernel 5.14.0-503.el9.x86_64 is newer than the running kernel 5.14.0-427.el9.x86_64", s.RebootReason)

	s = SplitKernels(debianKernels, "6.12.41+deb13-amd64") // Debian 13, before the reboot
	require.True(t, s.RebootPending)
	require.Equal(t, "installed kernel 6.12.48+deb13-amd64 is newer than the running kernel 6.12.41+deb13-amd64", s.RebootReason)
	require.Equal(t, "linux-image-6.12.41+deb13-amd64", s.Kernel.Package)

	// Alpine replaces linux-lts in place: the running kernel's package is gone.
	s = SplitKernels([]model.Package{{Ecosystem: "apk", Name: "linux-lts", Version: "6.6.32-r0"}}, "6.6.31-0-lts")
	require.Nil(t, s.Kernel)
	require.Equal(t, []string{"linux-lts"}, names(s.Other))
	require.Equal(t, "installed kernel 6.6.32-0-lts is newer than the running kernel 6.6.31-0-lts", s.RebootReason)

	// Newer headers without a newer image are not a pending reboot.
	s = SplitKernels([]model.Package{deb("linux-image-7.0.0-34-generic", "7.0.0-34.34", "linux"),
		deb("linux-headers-7.0.0-38", "7.0.0-38.38", "linux")}, "7.0.0-34-generic")
	require.False(t, s.RebootPending)
}

// TestKernelReleaseOf_UbuntuDerivatives: the per-release packages of Ubuntu's cloud, HWE and lowlatency
// kernels, as installed on Ubuntu 24.04 and 26.04 cloud images, each belong to their release; the
// flavourless derivative packages (linux-aws-headers-<abi>) to every flavour of that ABI.
func TestKernelReleaseOf_UbuntuDerivatives(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string // "" = not a per-release kernel package
	}{
		// Ubuntu 24.04, AWS
		{"linux-image-6.8.0-1021-aws", "6.8.0-1021-aws"},
		{"linux-modules-6.8.0-1021-aws", "6.8.0-1021-aws"},
		{"linux-headers-6.8.0-1021-aws", "6.8.0-1021-aws"},
		{"linux-tools-6.8.0-1021-aws", "6.8.0-1021-aws"},
		{"linux-cloud-tools-6.8.0-1021-aws", "6.8.0-1021-aws"},
		{"linux-buildinfo-6.8.0-1021-aws", "6.8.0-1021-aws"},
		{"linux-aws-headers-6.8.0-1021", "6.8.0-1021"},
		{"linux-aws-tools-6.8.0-1021", "6.8.0-1021"},
		{"linux-aws-cloud-tools-6.8.0-1021", "6.8.0-1021"},
		{"linux-aws-6.14-headers-6.14.0-1011", "6.14.0-1011"},
		// Ubuntu 24.04, Azure
		{"linux-image-6.8.0-1020-azure", "6.8.0-1020-azure"},
		{"linux-modules-extra-6.8.0-1020-azure", "6.8.0-1020-azure"},
		{"linux-azure-headers-6.8.0-1020", "6.8.0-1020"},
		{"linux-azure-tools-6.8.0-1020", "6.8.0-1020"},
		{"linux-azure-cloud-tools-6.8.0-1020", "6.8.0-1020"},
		{"linux-azure-6.11-headers-6.11.0-1015", "6.11.0-1015"},
		// Ubuntu 24.04, GCP and Oracle
		{"linux-image-6.8.0-1019-gcp", "6.8.0-1019-gcp"},
		{"linux-modules-extra-6.8.0-1019-gcp", "6.8.0-1019-gcp"},
		{"linux-gcp-headers-6.8.0-1019", "6.8.0-1019"},
		{"linux-gcp-tools-6.8.0-1019", "6.8.0-1019"},
		{"linux-image-6.8.0-1013-oracle", "6.8.0-1013-oracle"},
		{"linux-oracle-headers-6.8.0-1013", "6.8.0-1013"},
		{"linux-oracle-tools-6.8.0-1013", "6.8.0-1013"},
		// Ubuntu 24.04, HWE and lowlatency
		{"linux-image-6.11.0-19-generic", "6.11.0-19-generic"},
		{"linux-hwe-6.11-headers-6.11.0-19", "6.11.0-19"},
		{"linux-hwe-6.11-tools-6.11.0-19", "6.11.0-19"},
		{"linux-image-6.8.0-45-lowlatency", "6.8.0-45-lowlatency"},
		{"linux-lowlatency-headers-6.8.0-45", "6.8.0-45"},
		{"linux-lowlatency-tools-6.8.0-45", "6.8.0-45"},
		{"linux-lowlatency-hwe-6.11-headers-6.11.0-1011", "6.11.0-1011"},
		// Ubuntu 24.04, generic: flavourless tools of the source linux
		{"linux-tools-6.8.0-45", "6.8.0-45"},
		{"linux-cloud-tools-6.8.0-45", "6.8.0-45"},
		{"linux-cloud-tools-6.8.0-45-generic", "6.8.0-45-generic"},
		// Ubuntu 26.04 cloud images
		{"linux-image-7.0.0-1004-aws", "7.0.0-1004-aws"},
		{"linux-aws-headers-7.0.0-1004", "7.0.0-1004"},
		{"linux-aws-tools-7.0.0-1004", "7.0.0-1004"},
		{"linux-image-7.0.0-1003-azure", "7.0.0-1003-azure"},
		{"linux-azure-cloud-tools-7.0.0-1003", "7.0.0-1003"},
		{"linux-modules-extra-7.0.0-1005-gcp", "7.0.0-1005-gcp"},
		{"linux-gcp-headers-7.0.0-1005", "7.0.0-1005"},
		// Meta and version-less packages: never kernel packages.
		{"linux-aws", ""},
		{"linux-image-aws", ""},
		{"linux-headers-aws", ""},
		{"linux-tools-aws", ""},
		{"linux-tools-common", ""},
		{"linux-cloud-tools-common", ""},
		{"linux-azure", ""},
		{"linux-generic-hwe-24.04", ""},
		{"linux-image-generic-hwe-24.04", ""},
	} {
		got, ok := KernelReleaseOf(deb(tc.name, "1", "linux"))
		require.Equal(t, tc.want != "", ok, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}
}

// TestKernels_OnlyRunningDerivativeABIKept: on an AWS node running 6.8.0-1021-aws with 6.8.0-1018-aws still
// installed, only the running ABI's packages are kept, flavourless derivative headers and tools included.
func TestKernels_OnlyRunningDerivativeABIKept(t *testing.T) {
	aws := func(name, version string) model.Package { return deb(name, version, "linux-aws") }
	pkgs := []model.Package{
		deb("linux-image-6.8.0-1021-aws", "6.8.0-1021.23", "linux-signed-aws"), aws("linux-modules-6.8.0-1021-aws", "6.8.0-1021.23"),
		aws("linux-headers-6.8.0-1021-aws", "6.8.0-1021.23"), aws("linux-aws-headers-6.8.0-1021", "6.8.0-1021.23"),
		aws("linux-tools-6.8.0-1021-aws", "6.8.0-1021.23"), aws("linux-aws-tools-6.8.0-1021", "6.8.0-1021.23"),
		aws("linux-aws-cloud-tools-6.8.0-1021", "6.8.0-1021.23"), aws("linux-cloud-tools-6.8.0-1021-aws", "6.8.0-1021.23"),
		deb("linux-image-6.8.0-1018-aws", "6.8.0-1018.19", "linux-signed-aws"), aws("linux-modules-6.8.0-1018-aws", "6.8.0-1018.19"),
		aws("linux-headers-6.8.0-1018-aws", "6.8.0-1018.19"), aws("linux-aws-headers-6.8.0-1018", "6.8.0-1018.19"),
		aws("linux-tools-6.8.0-1018-aws", "6.8.0-1018.19"), aws("linux-aws-tools-6.8.0-1018", "6.8.0-1018.19"),
		aws("linux-aws-cloud-tools-6.8.0-1018", "6.8.0-1018.19"),
		deb("linux-aws", "6.8.0.1021.23", "linux-meta-aws"), deb("linux-image-aws", "6.8.0.1021.23", "linux-meta-aws"),
		deb("linux-tools-common", "6.8.0-45.45", "linux"), deb("openssl", "3.0.13-0ubuntu3.4", "openssl"),
	}
	s := SplitKernels(pkgs, "6.8.0-1021-aws")
	require.Equal(t, []string{"linux-image-6.8.0-1021-aws", "linux-modules-6.8.0-1021-aws", "linux-headers-6.8.0-1021-aws",
		"linux-aws-headers-6.8.0-1021", "linux-tools-6.8.0-1021-aws", "linux-aws-tools-6.8.0-1021", "linux-aws-cloud-tools-6.8.0-1021",
		"linux-cloud-tools-6.8.0-1021-aws", "linux-aws", "linux-image-aws", "linux-tools-common", "openssl"}, names(s.Running))
	require.Equal(t, []string{"linux-image-6.8.0-1018-aws", "linux-modules-6.8.0-1018-aws", "linux-headers-6.8.0-1018-aws",
		"linux-aws-headers-6.8.0-1018", "linux-tools-6.8.0-1018-aws", "linux-aws-tools-6.8.0-1018", "linux-aws-cloud-tools-6.8.0-1018"},
		names(s.Other))
	require.Equal(t, "linux-image-6.8.0-1021-aws", s.Kernel.Package)
	require.False(t, s.RebootPending)

	// An HWE node: the running 6.11 kernel's flavourless HWE packages are kept, the GA 6.8 ones are not.
	hwe := []model.Package{
		deb("linux-image-6.11.0-19-generic", "6.11.0-19.19~24.04.1", "linux-signed-hwe-6.11"),
		deb("linux-hwe-6.11-headers-6.11.0-19", "6.11.0-19.19~24.04.1", "linux-hwe-6.11"),
		deb("linux-hwe-6.11-tools-6.11.0-19", "6.11.0-19.19~24.04.1", "linux-hwe-6.11"),
		deb("linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed"), deb("linux-headers-6.8.0-45", "6.8.0-45.45", "linux"),
		deb("linux-tools-6.8.0-45", "6.8.0-45.45", "linux"),
	}
	s = SplitKernels(hwe, "6.11.0-19-generic")
	require.Equal(t, []string{"linux-image-6.11.0-19-generic", "linux-hwe-6.11-headers-6.11.0-19", "linux-hwe-6.11-tools-6.11.0-19"},
		names(s.Running))
	require.Equal(t, []string{"linux-image-6.8.0-45-generic", "linux-headers-6.8.0-45", "linux-tools-6.8.0-45"}, names(s.Other))
}
