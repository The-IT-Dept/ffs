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
